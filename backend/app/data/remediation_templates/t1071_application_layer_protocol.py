"""
T1071 - Application Layer Protocol

Adversaries use application layer protocols to blend malicious C2 traffic with legitimate network activity.
Commands and results are embedded within standard protocol exchanges across web, DNS, mail, and other protocols.
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
    technique_id="T1071",
    technique_name="Application Layer Protocol",
    tactic_ids=["TA0011"],  # Command and Control
    mitre_url="https://attack.mitre.org/techniques/T1071/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit OSI application layer protocols to evade detection by blending "
            "malicious traffic with legitimate network activity. Commands and results are embedded "
            "within standard protocol exchanges including web protocols, file transfer protocols, "
            "email protocols, DNS, and publish/subscribe protocols. In cloud environments, attackers "
            "leverage legitimate cloud services and APIs to communicate whilst appearing as normal traffic."
        ),
        attacker_goal="Establish covert command and control channels using legitimate application protocols",
        why_technique=[
            "Blends malicious traffic with legitimate business communications",
            "Bypasses traditional firewall rules and network policies",
            "SSL/TLS encryption conceals command content",
            "Cloud APIs provide trusted communication channels",
            "Difficult to distinguish from normal application behaviour",
            "Protocol tunnelling enables multi-stage attacks",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Application layer protocol abuse is a fundamental C2 technique with high prevalence. "
            "Its ability to blend with legitimate traffic makes detection challenging. Cloud environments "
            "amplify the risk as organisations routinely communicate with numerous external services. "
            "High severity due to enabling persistent unauthorised access and data exfiltration."
        ),
        business_impact=[
            "Unauthorised command and control access",
            "Data exfiltration through trusted protocols",
            "Compliance violations from undetected malicious traffic",
            "Prolonged attacker persistence and dwell time",
            "Potential for lateral movement and privilege escalation",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1567", "T1048"],  # Exfiltration techniques
        often_follows=["T1078.004", "T1190", "T1566"],  # Initial Access techniques
    ),
    detection_strategies=[
        # Strategy 1: AWS - Unusual DNS Query Patterns
        DetectionStrategy(
            strategy_id="t1071-aws-dns-anomaly",
            name="AWS Route 53 DNS Query Anomaly Detection",
            description="Detect unusual DNS query patterns that may indicate DNS-based C2 communications or tunnelling.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r"""fields @timestamp, query_name, query_type, srcaddr
| filter query_type = "TXT" or query_type = "NULL" or query_type = "ANY"
| filter query_name like /[a-f0-9]{32,}/ or query_name like /[A-Za-z0-9+\/=]{40,}/
| stats count() as query_count by srcaddr, query_name, query_type
| filter query_count > 10
| sort query_count desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual DNS query patterns for C2 detection

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for suspicious DNS queries
  DnsQueryRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Detect suspicious DNS query patterns
      EventPattern:
        source: [aws.route53]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - ChangeResourceRecordSets
          requestParameters:
            changeBatch:
              changes:
                resourceRecordSet:
                  type: [TXT, NULL, CNAME]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: Topic policy to allow EventBridge
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
                terraform_template="""# Detect unusual DNS query patterns for C2

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "dns_alerts" {
  name = "dns-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.dns_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for suspicious DNS operations
resource "aws_cloudwatch_event_rule" "dns_anomaly" {
  name        = "dns-query-anomaly-detection"
  description = "Detect suspicious DNS record changes"

  event_pattern = jsonencode({
    source      = ["aws.route53"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["ChangeResourceRecordSets"]
      requestParameters = {
        changeBatch = {
          changes = {
            resourceRecordSet = {
              type = ["TXT", "NULL", "CNAME"]
            }
          }
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.dns_anomaly.name
  arn  = aws_sns_topic.dns_alerts.arn
}

# Step 3: SNS topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.dns_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.dns_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="Suspicious DNS Query Pattern Detected",
                alert_description_template="Unusual DNS queries detected from {srcaddr}. Query pattern may indicate DNS tunnelling or C2 activity.",
                investigation_steps=[
                    "Identify the source instance making the queries",
                    "Review the DNS query types and frequency",
                    "Check for Base64 or hexadecimal encoded query strings",
                    "Analyse query length and entropy for data exfiltration patterns",
                    "Review instance processes and network connections",
                    "Correlate with other suspicious activities from the source",
                ],
                containment_actions=[
                    "Isolate the source instance from the network",
                    "Block suspicious DNS queries via Route 53 Resolver DNS Firewall",
                    "Review and restrict instance IAM permissions",
                    "Enable enhanced DNS query logging",
                    "Implement DNS sinkholing for known C2 domains",
                    "Review security group rules for unnecessary egress",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate use of TXT records for SPF/DKIM/DMARC and monitoring tools. Establish baseline for normal DNS patterns.",
            detection_coverage="75% - detects DNS-based C2 but may miss other protocols",
            evasion_considerations="Attackers may use legitimate DNS services or low-frequency queries to evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "Route 53 Query Logging enabled"],
        ),
        # Strategy 2: AWS - Unusual HTTP/HTTPS Patterns
        DetectionStrategy(
            strategy_id="t1071-aws-http-anomaly",
            name="AWS VPC Flow Logs HTTP/HTTPS Anomaly Detection",
            description="Detect unusual HTTP/HTTPS traffic patterns including beaconing behaviour and unusual user agents.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, protocol, bytes
| filter dstPort in [80, 443, 8080, 8443]
| filter protocol = 6
| stats count() as connection_count, sum(bytes) as total_bytes by srcAddr, dstAddr, bin(5m)
| filter connection_count > 50 and total_bytes < 10000
| sort connection_count desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect HTTP/HTTPS beaconing patterns indicative of C2

Parameters:
  VpcId:
    Type: String
    Description: VPC ID to monitor
  AlertEmail:
    Type: String
    Description: Email address for alerts

Resources:
  # Step 1: VPC Flow Logs
  FlowLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/vpc/flowlogs-c2-detection
      RetentionInDays: 7

  FlowLogRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: vpc-flow-logs.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: CloudWatchLogs
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: !GetAtt FlowLogGroup.Arn

  FlowLog:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceType: VPC
      ResourceIds:
        - !Ref VpcId
      TrafficType: ALL
      LogDestinationType: cloud-watch-logs
      LogGroupName: !Ref FlowLogGroup
      DeliverLogsPermissionArn: !GetAtt FlowLogRole.Arn

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: CloudWatch alarm for beaconing pattern
  BeaconAlarm:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref FlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport="443", protocol="6", packets, bytes<10000, ...]'
      MetricTransformations:
        - MetricName: PotentialBeaconing
          MetricNamespace: Security/C2Detection
          MetricValue: '1'
          DefaultValue: 0""",
                terraform_template="""# Detect HTTP/HTTPS beaconing patterns

variable "vpc_id" {
  type        = string
  description = "VPC ID to monitor"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Step 1: CloudWatch Log Group for VPC Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flowlogs-c2-detection"
  retention_in_days = 7
}

# Step 2: IAM role for VPC Flow Logs
resource "aws_iam_role" "flow_logs" {
  name = "vpc-flow-logs-c2-detection"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

# Step 3: VPC Flow Log
resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = var.vpc_id
}""",
                alert_severity="high",
                alert_title="HTTP/HTTPS Beaconing Pattern Detected",
                alert_description_template="Beaconing behaviour detected from {srcAddr} to {dstAddr}. Regular small connections may indicate C2 activity.",
                investigation_steps=[
                    "Identify the source instance and its purpose",
                    "Review connection timing and frequency patterns",
                    "Analyse application logs for the source instance",
                    "Check destination IP reputation and ownership",
                    "Review HTTP headers and user agents if available",
                    "Examine instance for malware or backdoors",
                ],
                containment_actions=[
                    "Block suspicious destination IPs via security groups",
                    "Isolate affected instances from production network",
                    "Review and restrict outbound internet access",
                    "Enable AWS WAF for application-layer protection",
                    "Deploy endpoint detection and response (EDR) tools",
                    "Review IAM roles and instance profiles",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Establish baselines for normal application behaviour. Whitelist legitimate monitoring and health check traffic.",
            detection_coverage="70% - detects beaconing patterns but may miss irregular C2",
            evasion_considerations="Attackers may randomise timing and payload sizes to evade pattern detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs"],
        ),
        # Strategy 3: AWS - GuardDuty C2 Detection
        DetectionStrategy(
            strategy_id="t1071-aws-guardduty",
            name="AWS GuardDuty C2 Activity Detection",
            description="Leverage AWS GuardDuty to detect known C2 activity and suspicious network behaviour.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Backdoor:EC2/C&CActivity.B!DNS",
                    "Backdoor:EC2/C&CActivity.B",
                    "Trojan:EC2/DNSDataExfiltration",
                    "Trojan:EC2/BlackholeTraffic",
                    "Trojan:EC2/DropPoint",
                    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Configure GuardDuty alerts for C2 detection

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

  # Step 2: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: EventBridge rule for C2 findings
  GuardDutyC2Rule:
    Type: AWS::Events::Rule
    Properties:
      Description: Alert on GuardDuty C2 findings
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          type:
            - prefix: Backdoor:EC2/C&CActivity
            - prefix: Trojan:EC2/DNSDataExfiltration
            - prefix: Trojan:EC2/BlackholeTraffic
            - prefix: Trojan:EC2/DropPoint
      State: ENABLED
      Targets:
        - Id: AlertTopic
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
                terraform_template="""# Configure GuardDuty for C2 detection

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
  name = "guardduty-c2-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule for C2 findings
resource "aws_cloudwatch_event_rule" "guardduty_c2" {
  name        = "guardduty-c2-detection"
  description = "Alert on GuardDuty C2 findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor:EC2/C&CActivity" },
        { prefix = "Trojan:EC2/DNSDataExfiltration" },
        { prefix = "Trojan:EC2/BlackholeTraffic" },
        { prefix = "Trojan:EC2/DropPoint" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.guardduty_c2.name
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
                alert_title="GuardDuty C2 Activity Detected",
                alert_description_template="GuardDuty detected {type} on instance {resource.instanceDetails.instanceId}. This indicates potential command and control activity.",
                investigation_steps=[
                    "Review GuardDuty finding details and severity",
                    "Identify affected EC2 instances and their roles",
                    "Check instance network connections and processes",
                    "Review CloudTrail logs for suspicious API activity",
                    "Analyse VPC Flow Logs for the timeframe",
                    "Check for lateral movement from affected instances",
                ],
                containment_actions=[
                    "Isolate affected instances immediately",
                    "Create forensic snapshots before remediation",
                    "Revoke instance IAM role credentials",
                    "Block malicious IPs via security groups and NACLs",
                    "Review and rotate any exposed credentials",
                    "Deploy replacement instances from clean images",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review and suppress findings for known security tools and monitoring systems. Update threat intelligence feed regularly.",
            detection_coverage="90% - GuardDuty uses threat intelligence and ML for high accuracy",
            evasion_considerations="Zero-day C2 infrastructure may not be in threat intelligence feeds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$30-100 depending on data volume",
            prerequisites=["GuardDuty enabled", "VPC Flow Logs", "DNS Logs"],
        ),
        # Strategy 4: GCP - Cloud Logging C2 Pattern Detection
        DetectionStrategy(
            strategy_id="t1071-gcp-http-anomaly",
            name="GCP VPC Flow Logs C2 Pattern Detection",
            description="Detect suspicious HTTP/HTTPS traffic patterns in GCP VPC Flow Logs indicative of C2 activity.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port:(443 OR 80 OR 8080 OR 8443)
jsonPayload.connection.protocol=6
jsonPayload.bytes_sent<10000
jsonPayload.packets>50""",
                gcp_terraform_template="""# GCP: Detect C2 beaconing patterns in VPC Flow Logs

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
  display_name = "Security Alerts - C2 Detection"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for beaconing patterns
resource "google_logging_metric" "c2_beaconing" {
  name   = "c2-beaconing-pattern"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName=~"projects/.*/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.dest_port:(443 OR 80 OR 8080 OR 8443)
    jsonPayload.connection.protocol=6
    jsonPayload.bytes_sent<10000
    jsonPayload.packets>50
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "c2_detection" {
  display_name = "C2 Beaconing Pattern Detected"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious beaconing behaviour detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.c2_beaconing.name}\""
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
}""",
                alert_severity="high",
                alert_title="GCP: C2 Beaconing Pattern Detected",
                alert_description_template="Beaconing behaviour detected in VPC Flow Logs. Small, frequent connections may indicate command and control activity.",
                investigation_steps=[
                    "Identify source VM instance and its project",
                    "Review connection patterns and destination IPs",
                    "Check destination IP reputation using threat intelligence",
                    "Analyse Cloud Logging for application-level logs",
                    "Review VM metadata and startup scripts",
                    "Check for unauthorised changes to the instance",
                ],
                containment_actions=[
                    "Isolate affected VM instances using firewall rules",
                    "Create snapshots for forensic analysis",
                    "Revoke service account credentials",
                    "Block malicious IPs via Cloud Armor or VPC firewall",
                    "Enable VPC Service Controls to prevent data exfiltration",
                    "Review IAM permissions for affected resources",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Establish baselines for legitimate application traffic patterns. Whitelist known monitoring and health check services.",
            detection_coverage="70% - detects beaconing but may miss irregular C2 patterns",
            evasion_considerations="Attackers may randomise connection timing and sizes to evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging"],
        ),
        # Strategy 5: GCP - Security Command Centre Threat Detection
        DetectionStrategy(
            strategy_id="t1071-gcp-scc",
            name="GCP Security Command Centre Malware Detection",
            description="Leverage Security Command Centre Event Threat Detection to identify C2 activity and malware communications.",
            detection_type=DetectionType.SECURITY_COMMAND_CENTER,
            aws_service="n/a",
            gcp_service="security_command_center",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                scc_finding_categories=[
                    "Malware: Cryptomining Bad Domain",
                    "Malware: Bad Domain",
                    "Malware: Bad IP",
                    "Persistence: IAM Anomalous Grant",
                    "Initial Access: Suspicious Login",
                ],
                gcp_terraform_template="""# GCP: Configure Security Command Centre for C2 detection

variable "organization_id" {
  type        = string
  description = "GCP organisation ID"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Enable Security Command Centre (requires organisation-level access)
# Note: SCC must be enabled manually or via organisation policies

# Step 2: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - SCC"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Pub/Sub topic for SCC findings
resource "google_pubsub_topic" "scc_findings" {
  name = "scc-c2-findings"
}

resource "google_pubsub_subscription" "scc_findings" {
  name  = "scc-c2-findings-sub"
  topic = google_pubsub_topic.scc_findings.name

  ack_deadline_seconds = 20

  push_config {
    push_endpoint = "https://example.com/webhook"  # Replace with your SIEM/SOAR endpoint
  }
}

# Note: SCC notification configs require organization-level API access
# Configure via: gcloud scc notifications create
# Or use google_scc_notification_config resource with appropriate permissions""",
                alert_severity="critical",
                alert_title="GCP: Malicious C2 Activity Detected by SCC",
                alert_description_template="Security Command Centre detected {category} on {resourceName}. This indicates potential command and control activity.",
                investigation_steps=[
                    "Review Security Command Centre finding details",
                    "Identify affected GCP resources and projects",
                    "Check Cloud Audit Logs for suspicious API calls",
                    "Review VPC Flow Logs for network connections",
                    "Analyse VM instance metadata and configurations",
                    "Check for lateral movement across projects",
                ],
                containment_actions=[
                    "Isolate affected resources immediately",
                    "Create snapshots for forensic investigation",
                    "Revoke compromised service account keys",
                    "Enable VPC Service Controls perimeter",
                    "Review and rotate any exposed credentials",
                    "Apply organisation policy constraints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review findings for legitimate security tools and development environments. Configure SCC muting rules for known benign activities.",
            detection_coverage="85% - SCC uses threat intelligence and behavioural analysis",
            evasion_considerations="Custom or zero-day C2 infrastructure may not be detected initially",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$50-150 depending on assets",
            prerequisites=[
                "Security Command Centre enabled",
                "Event Threat Detection enabled",
            ],
        ),
        # Strategy 6: AWS - Unusual Protocol Usage Detection
        DetectionStrategy(
            strategy_id="t1071-aws-protocol-anomaly",
            name="AWS Unusual Protocol and Port Detection",
            description="Detect unusual network protocols or non-standard port usage that may indicate protocol tunnelling or C2.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, protocol
| filter dstPort not in [80, 443, 22, 3389, 53]
| filter protocol in [6, 17]
| stats count() as connection_count by srcAddr, dstAddr, dstPort, protocol
| filter connection_count > 20
| sort connection_count desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual protocol and port usage for C2 detection

Parameters:
  VpcFlowLogGroup:
    Type: String
    Description: CloudWatch Log Group for VPC Flow Logs
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for unusual protocol usage
  UnusualProtocolMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VpcFlowLogGroup
      FilterPattern: '[version, account, eni, src, dst, srcport, dstport!=80 && dstport!=443 && dstport!=22 && dstport!=3389 && dstport!=53, protocol=6 || protocol=17, ...]'
      MetricTransformations:
        - MetricName: UnusualProtocolConnections
          MetricNamespace: Security/C2Detection
          MetricValue: '1'
          DefaultValue: 0

  # Step 3: CloudWatch alarm
  ProtocolAnomalyAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnusualProtocolUsage
      AlarmDescription: Alert on unusual protocol or port usage
      MetricName: UnusualProtocolConnections
      Namespace: Security/C2Detection
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Detect unusual protocol and port usage

variable "vpc_flow_log_group" {
  type        = string
  description = "CloudWatch Log Group for VPC Flow Logs"
}

variable "alert_email" {
  type        = string
  description = "Email address for alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "protocol_alerts" {
  name = "unusual-protocol-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.protocol_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch metric filter for unusual ports
resource "aws_cloudwatch_log_metric_filter" "unusual_protocol" {
  name           = "unusual-protocol-usage"
  log_group_name = var.vpc_flow_log_group

  # Match connections on non-standard ports
  pattern = "[version, account, eni, src, dst, srcport, dstport!=80 && dstport!=443 && dstport!=22 && dstport!=3389 && dstport!=53, protocol=6 || protocol=17, ...]"

  metric_transformation {
    name      = "UnusualProtocolConnections"
    namespace = "Security/C2Detection"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "protocol_anomaly" {
  alarm_name          = "UnusualProtocolUsage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UnusualProtocolConnections"
  namespace           = "Security/C2Detection"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  alarm_description   = "Alert on unusual protocol or port usage"
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.protocol_alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Unusual Network Protocol or Port Detected",
                alert_description_template="Unusual protocol usage detected from {srcAddr} to {dstAddr}:{dstPort}. May indicate protocol tunnelling or C2.",
                investigation_steps=[
                    "Identify source and destination instances",
                    "Determine the application using the unusual protocol/port",
                    "Check if this is a legitimate application requirement",
                    "Review instance security groups and network ACLs",
                    "Analyse process list and network connections on source",
                    "Check for protocol tunnelling tools or proxies",
                ],
                containment_actions=[
                    "Review and restrict security group egress rules",
                    "Block non-essential protocols and ports",
                    "Enable VPC Flow Logs for enhanced visibility",
                    "Implement application-aware firewall rules",
                    "Deploy intrusion detection systems (IDS)",
                    "Review and update network segmentation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Identify and whitelist all legitimate applications using non-standard ports. Document and baseline expected protocol usage.",
            detection_coverage="60% - broad detection but requires tuning",
            evasion_considerations="Attackers using standard ports (80, 443) will not be detected by this rule",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs"],
        ),
    ],
    recommended_order=[
        "t1071-aws-guardduty",
        "t1071-gcp-scc",
        "t1071-aws-dns-anomaly",
        "t1071-aws-http-anomaly",
        "t1071-gcp-http-anomaly",
        "t1071-aws-protocol-anomaly",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+25% improvement for Command and Control tactic detection",
)
