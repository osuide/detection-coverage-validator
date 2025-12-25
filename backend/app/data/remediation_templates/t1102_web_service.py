"""
T1102 - Web Service

Adversaries leverage legitimate external web services as command and control relays
for compromised systems, using platforms like Google, Microsoft, Dropbox, and GitHub.
Used by APT32, APT41, APT42, Turla, FIN6, FIN8, Gamaredon Group, TeamTNT.
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
    technique_id="T1102",
    technique_name="Web Service",
    tactic_ids=["TA0011"],
    mitre_url="https://attack.mitre.org/techniques/T1102/",
    threat_context=ThreatContext(
        description=(
            "Adversaries leverage legitimate external web services as command and control "
            "relays for compromised systems. This technique exploits the likelihood that "
            "organisations already communicate with these services, providing cover for "
            "malicious activity. Popular platforms like Google, Microsoft, Dropbox, GitHub, "
            "Discord, and Slack enable attackers to hide in expected noise whilst benefiting "
            "from SSL/TLS encryption that obscures their infrastructure."
        ),
        attacker_goal="Establish covert command and control channels using legitimate web services",
        why_technique=[
            "Blends with normal organisational traffic",
            "SSL/TLS encryption hides communication content",
            "Firewall rules typically permit these services",
            "Difficult to block without impacting business operations",
            "Free tier services require minimal attacker investment",
            "Built-in reliability and uptime",
            "Multi-platform support (web, mobile, desktop)",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Web service-based C2 is extremely difficult to detect and block due to "
            "legitimate business use. SSL/TLS encryption prevents deep packet inspection, "
            "and blocking these services impacts productivity. Attackers benefit from "
            "high-availability infrastructure without operational costs."
        ),
        business_impact=[
            "Persistent unauthorised access to environment",
            "Data exfiltration via trusted channels",
            "Command execution on compromised systems",
            "Difficult incident response and containment",
            "Extended dwell time due to detection challenges",
            "Potential regulatory violations",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1567", "T1530", "T1485", "T1486"],
        often_follows=["T1190", "T1078.004", "T1552.005", "T1105"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1102-aws-unusual-api",
            name="AWS Unusual Web Service API Calls",
            description="Detect instances or users making unexpected API calls to web services.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, sourceIPAddress, userAgent, @message
| filter userAgent like /(?i)(discord|slack|dropbox|pastebin|github|telegram|graph.*api)/
| filter eventSource != "s3.amazonaws.com"
| stats count(*) as api_calls by userIdentity.arn, userAgent, sourceIPAddress, bin(5m)
| filter api_calls > 20
| sort api_calls desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual web service API calls from cloud resources

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  VpcFlowLogGroup:
    Type: String
    Description: VPC Flow Logs log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: web-service-c2-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for web service API calls
  WebServiceMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.userAgent = "*discord*" || $.userAgent = "*slack*" || $.userAgent = "*dropbox*" || $.userAgent = "*pastebin*" || $.userAgent = "*github*" || $.userAgent = "*telegram*" }'
      MetricTransformations:
        - MetricName: WebServiceAPICalls
          MetricNamespace: Security/C2
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Create alarm for suspicious web service activity
  WebServiceAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: WebService-C2-Activity
      AlarmDescription: Detects unusual web service API calls indicative of C2
      MetricName: WebServiceAPICalls
      Namespace: Security/C2
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 25
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic
      TreatMissingData: notBreaching""",
                terraform_template="""# AWS: Detect unusual web service API calls

variable "cloudtrail_log_group" {
  description = "CloudTrail log group name"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "web-service-c2-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for web service API calls
resource "aws_cloudwatch_log_metric_filter" "web_service_calls" {
  name           = "web-service-api-calls"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.userAgent = \"*discord*\" || $.userAgent = \"*slack*\" || $.userAgent = \"*dropbox*\" || $.userAgent = \"*pastebin*\" || $.userAgent = \"*github*\" || $.userAgent = \"*telegram*\" }"

  metric_transformation {
    name          = "WebServiceAPICalls"
    namespace     = "Security/C2"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for suspicious web service activity
resource "aws_cloudwatch_metric_alarm" "web_service_alert" {
  alarm_name          = "WebService-C2-Activity"
  alarm_description   = "Detects unusual web service API calls indicative of C2"
  metric_name         = "WebServiceAPICalls"
  namespace           = "Security/C2"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 25
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="high",
                alert_title="Unusual Web Service API Activity Detected",
                alert_description_template="Resource {userIdentity.arn} making repeated calls to web services via {userAgent}.",
                investigation_steps=[
                    "Identify the resource making web service calls",
                    "Review the user agent patterns and frequency",
                    "Check if the service is authorised for business use",
                    "Analyse network traffic to/from the resource",
                    "Review CloudTrail for recent privilege escalations",
                    "Check for data staging or collection activities",
                ],
                containment_actions=[
                    "Isolate affected instance via security groups",
                    "Revoke IAM credentials for compromised identity",
                    "Block web service domains at VPC level if feasible",
                    "Enable VPC endpoints to prevent external calls",
                    "Create snapshot for forensic analysis",
                    "Review and restrict outbound internet access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised integration services and CI/CD pipelines",
            detection_coverage="60% - user agent-based detection",
            evasion_considerations="Custom user agents or encrypted traffic may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail enabled with management events",
                "CloudWatch Logs integration",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1102-aws-vpc-web-traffic",
            name="AWS VPC Abnormal Web Service Traffic",
            description="Detect unusual traffic patterns to known web services via VPC Flow Logs.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, protocol, bytes, packets
| filter dstPort in [80, 443, 8080, 8443]
| filter action = "ACCEPT"
| stats count(*) as connections, sum(bytes) as total_bytes by srcAddr, dstAddr, bin(5m)
| filter connections > 100 or total_bytes > 10485760
| sort connections desc""",
                terraform_template="""# AWS: Detect abnormal web service traffic patterns

variable "vpc_flow_log_group" {
  description = "VPC Flow Logs log group name"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "web-traffic-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for high-frequency connections
resource "aws_cloudwatch_log_metric_filter" "web_traffic" {
  name           = "abnormal-web-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport IN (80,443,8080,8443), protocol, packets > 100, bytes, ...]"

  metric_transformation {
    name          = "AbnormalWebConnections"
    namespace     = "Security/Network"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Create alarm for traffic anomalies
resource "aws_cloudwatch_metric_alarm" "web_traffic_alert" {
  alarm_name          = "Abnormal-Web-Service-Traffic"
  alarm_description   = "Detects unusual connection patterns to web services"
  metric_name         = "AbnormalWebConnections"
  namespace           = "Security/Network"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}""",
                alert_severity="medium",
                alert_title="Abnormal Web Service Traffic Pattern",
                alert_description_template="Instance {srcAddr} showing unusual connection patterns to {dstAddr}.",
                investigation_steps=[
                    "Identify source instance and its purpose",
                    "Resolve destination IP to service provider",
                    "Review connection frequency and data volume",
                    "Check for beaconing behaviour patterns",
                    "Analyse process-level network activity on instance",
                    "Correlate with CloudTrail API activity",
                ],
                containment_actions=[
                    "Block destination IP ranges if malicious",
                    "Modify security groups to restrict outbound",
                    "Isolate instance for investigation",
                    "Enable VPC Traffic Mirroring for deeper inspection",
                    "Implement Network Firewall rules",
                    "Review and tighten NACL rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Exclude known application servers, web scrapers, and monitoring systems",
            detection_coverage="55% - network pattern-based detection",
            evasion_considerations="Low and slow beaconing, randomised intervals, or protocol tunnelling may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1102-aws-guardduty",
            name="AWS GuardDuty C2 Activity Detection",
            description="Leverage GuardDuty to detect instances communicating with known C2 infrastructure.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Backdoor:EC2/C&CActivity.B",
                    "Backdoor:EC2/C&CActivity.B!DNS",
                    "Trojan:EC2/DNSDataExfiltration",
                    "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty detection for web service C2 activity

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for GuardDuty alerts
  GuardDutyAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: guardduty-c2-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for C2 findings
  GuardDutyC2Rule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-web-service-c2
      Description: Alert on GuardDuty C2 activity findings
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - Backdoor:EC2/C&CActivity.B
            - Backdoor:EC2/C&CActivity.B!DNS
            - Trojan:EC2/DNSDataExfiltration
            - UnauthorizedAccess:EC2/MaliciousIPCaller.Custom
      State: ENABLED
      Targets:
        - Arn: !Ref GuardDutyAlertTopic
          Id: SNSTarget

  # Step 3: Grant EventBridge permission to publish
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
                terraform_template="""# AWS: GuardDuty web service C2 detection

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create SNS topic for GuardDuty alerts
resource "aws_sns_topic" "guardduty_alerts" {
  name = "guardduty-c2-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for C2 findings
resource "aws_cloudwatch_event_rule" "guardduty_c2" {
  name        = "guardduty-web-service-c2"
  description = "Alert on GuardDuty C2 activity findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        "Backdoor:EC2/C&CActivity.B",
        "Backdoor:EC2/C&CActivity.B!DNS",
        "Trojan:EC2/DNSDataExfiltration",
        "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom"
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
                alert_description_template="Instance {instanceId} communicating with known C2 infrastructure.",
                investigation_steps=[
                    "Review GuardDuty finding details and severity",
                    "Identify malicious domain/IP from threat intelligence",
                    "Check instance for suspicious processes and network connections",
                    "Review CloudTrail for recent API activity from instance",
                    "Analyse instance metadata and user data",
                    "Check for persistence mechanisms and backdoors",
                ],
                containment_actions=[
                    "Immediately isolate affected instance",
                    "Revoke all associated IAM credentials",
                    "Block malicious IPs/domains at Network Firewall",
                    "Create forensic snapshot before termination",
                    "Rotate all secrets accessible to instance",
                    "Review and remove any unauthorised resources created",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty findings are vetted by threat intelligence; review trusted IP lists",
            detection_coverage="80% - leverages continuous threat intelligence updates",
            evasion_considerations="New or unknown C2 infrastructure not yet in threat feeds may evade",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$1-5 (requires GuardDuty)",
            prerequisites=["AWS GuardDuty enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1102-gcp-web-service",
            name="GCP Cloud Logging Web Service Activity",
            description="Detect GCP resources making unusual calls to external web services.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
(jsonPayload.connection.dest_ip=~"discord|slack|dropbox|pastebin|github|telegram" OR
 httpRequest.requestUrl=~"discord|slack|dropbox|pastebin|github|telegram")
NOT protoPayload.authenticationInfo.principalEmail=~"@your-domain.com"''',
                gcp_terraform_template="""# GCP: Detect web service C2 activity

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_email" {
  description = "Email for security alerts"
  type        = string
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Web Service C2"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for web service connections
resource "google_logging_metric" "web_service_c2" {
  name   = "web-service-c2-activity"
  filter = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.connection.dest_ip=~"discord|slack|dropbox|pastebin|github|telegram" OR
     httpRequest.requestUrl=~"discord|slack|dropbox|pastebin|github|telegram")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Instance making web service calls"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 3: Create alert policy for web service activity
resource "google_monitoring_alert_policy" "web_service_alert" {
  display_name = "Web Service C2 Activity"
  combiner     = "OR"

  conditions {
    display_name = "Unusual web service connections"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.web_service_c2.name}\" AND resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 20
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
                alert_title="GCP: Web Service C2 Activity",
                alert_description_template="Instance {instance_id} making unusual web service connections.",
                investigation_steps=[
                    "Identify the GCE instance and its purpose",
                    "Review Cloud Logging for detailed connection information",
                    "Check service account permissions and recent usage",
                    "Analyse network traffic via VPC Flow Logs",
                    "Review recent Compute Engine API calls",
                    "Check for unauthorised software installations",
                ],
                containment_actions=[
                    "Isolate instance using firewall rules",
                    "Revoke service account credentials",
                    "Create persistent disk snapshot for forensics",
                    "Block malicious domains via Cloud DNS policies",
                    "Enable VPC Service Controls",
                    "Stop or delete compromised instance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist authorised integrations and deployment pipelines",
            detection_coverage="65% - detects common web service C2 channels",
            evasion_considerations="Custom domains, IP-based connections, or encrypted tunnels may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging configured"],
        ),
        DetectionStrategy(
            strategy_id="t1102-gcp-dns-queries",
            name="GCP Cloud DNS Suspicious Query Patterns",
            description="Detect unusual DNS query patterns to web service domains.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_dns",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="dns_query"
jsonPayload.queryName=~"(discord|slack|dropbox|pastebin|github|telegram|api\\.telegram\\.org|api\\.slack\\.com)"
jsonPayload.responseCode="NOERROR"''',
                gcp_terraform_template="""# GCP: Detect suspicious DNS queries to web services

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
  display_name = "Security Alerts - DNS Queries"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for suspicious DNS queries
resource "google_logging_metric" "dns_queries" {
  name   = "suspicious-dns-web-services"
  filter = <<-EOT
    resource.type="dns_query"
    jsonPayload.queryName=~"(discord|slack|dropbox|pastebin|github|telegram|api\\.telegram\\.org|api\\.slack\\.com)"
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
    "source_ip" = "EXTRACT(jsonPayload.sourceIP)"
  }
}

# Step 3: Create alert for high-frequency DNS queries
resource "google_monitoring_alert_policy" "dns_alert" {
  display_name = "Suspicious Web Service DNS Queries"
  combiner     = "OR"

  conditions {
    display_name = "High frequency DNS queries detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.dns_queries.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.source_ip"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "3600s"
  }
}""",
                alert_severity="medium",
                alert_title="GCP: Suspicious DNS Query Patterns",
                alert_description_template="High frequency DNS queries to web service domains from {source_ip}.",
                investigation_steps=[
                    "Identify source IP and associated resources",
                    "Review query frequency and timing patterns",
                    "Check for DNS beaconing behaviour",
                    "Analyse response data sizes for exfiltration",
                    "Review Cloud Logging for related activities",
                    "Check for DNS tunnelling indicators",
                ],
                containment_actions=[
                    "Block suspicious domains via Cloud DNS policies",
                    "Isolate source resource via firewall rules",
                    "Enable DNS Security Extensions (DNSSEC)",
                    "Implement Cloud Armor rules if web-facing",
                    "Review and restrict DNS query permissions",
                    "Enable VPC Service Controls for DNS",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal DNS query patterns and exclude legitimate integrations",
            detection_coverage="60% - DNS-level pattern detection",
            evasion_considerations="Direct IP connections, custom DNS resolvers, or DoH/DoT may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["Cloud DNS Query Logging enabled"],
        ),
    ],
    recommended_order=[
        "t1102-aws-guardduty",
        "t1102-gcp-web-service",
        "t1102-aws-unusual-api",
        "t1102-aws-vpc-web-traffic",
        "t1102-gcp-dns-queries",
    ],
    total_effort_hours=6.5,
    coverage_improvement="+20% improvement for Command and Control tactic",
)
