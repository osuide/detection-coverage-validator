"""
T1573 - Encrypted Channel

Adversaries employ encryption algorithms to mask command-and-control traffic rather than
relying on inherent protocol protections. Detectable through TLS/SSL anomalies and unusual encrypted patterns.
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
    technique_id="T1573",
    technique_name="Encrypted Channel",
    tactic_ids=["TA0011"],  # Command and Control
    mitre_url="https://attack.mitre.org/techniques/T1573/",
    threat_context=ThreatContext(
        description=(
            "Adversaries employ encryption algorithms to mask command-and-control traffic rather than "
            "relying on inherent protocol protections. Whilst encryption algorithms themselves may be robust, "
            "implementations remain vulnerable to reverse engineering when secret keys are embedded in malware "
            "samples or configuration files. In cloud environments, attackers leverage both symmetric and "
            "asymmetric cryptography to establish encrypted C2 channels that blend with legitimate TLS/SSL traffic. "
            "Detection focuses on TLS/SSL anomalies, unusual encrypted connections, and non-standard cryptographic implementations."
        ),
        attacker_goal="Establish encrypted command and control channels to conceal malicious communications",
        why_technique=[
            "Conceals C2 traffic from network monitoring tools",
            "Bypasses traditional signature-based detection systems",
            "Blends with legitimate encrypted business traffic",
            "Prevents exposure of commands and exfiltrated data",
            "Protects C2 infrastructure from identification",
            "Enables persistent covert communications",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Encrypted channels are fundamental to modern C2 operations, with very high prevalence across "
            "threat actors. The technique's effectiveness in concealing malicious communications whilst "
            "blending with legitimate traffic makes it particularly dangerous. In cloud environments with "
            "high volumes of encrypted traffic, detection is challenging. High severity due to enabling "
            "persistent unauthorised access, data exfiltration, and prolonged attacker dwell time."
        ),
        business_impact=[
            "Concealed command and control communications",
            "Undetected data exfiltration",
            "Extended attacker persistence and dwell time",
            "Difficulty in forensic investigation",
            "Compliance violations from undetected breaches",
            "Potential for sustained espionage or sabotage",
        ],
        typical_attack_phase="command_and_control",
        often_precedes=["T1041", "T1048", "T1567"],  # Exfiltration techniques
        often_follows=["T1078.004", "T1190", "T1566"],  # Initial Access techniques
    ),
    detection_strategies=[
        # Strategy 1: AWS - Unusual TLS/SSL Patterns
        DetectionStrategy(
            strategy_id="t1573-aws-tls-anomaly",
            name="AWS VPC Flow Logs TLS/SSL Anomaly Detection",
            description="Detect unusual TLS/SSL connection patterns including non-standard ports, asymmetric traffic, and suspicious certificate behaviours.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, protocol, bytes
| filter protocol = 6
| filter dstPort not in [443, 8443]
| filter bytes > 0
| stats count() as connection_count, sum(bytes) as total_bytes by srcAddr, dstAddr, dstPort
| filter connection_count > 50 and total_bytes < 50000
| sort connection_count desc
| limit 100""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual TLS/SSL connection patterns for encrypted C2 detection

Parameters:
  VpcId:
    Type: String
    Description: VPC ID to monitor
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: VPC Flow Logs configuration
  FlowLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/vpc/flowlogs-tls-detection
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

  # Step 3: CloudWatch metric filter for unusual encrypted connections
  TlsAnomalyMetric:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref FlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport!=443 && dstport!=8443, protocol="6", ...]'
      MetricTransformations:
        - MetricName: UnusualEncryptedConnections
          MetricNamespace: Security/C2Detection
          MetricValue: '1'
          DefaultValue: 0""",
                terraform_template="""# Detect unusual TLS/SSL connection patterns

variable "vpc_id" {
  type        = string
  description = "VPC ID to monitor"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: CloudWatch Log Group for VPC Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flowlogs-tls-detection"
  retention_in_days = 7
}

# Step 2: IAM role for VPC Flow Logs
resource "aws_iam_role" "flow_logs" {
  name = "vpc-flow-logs-tls-detection"

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
                alert_title="Unusual TLS/SSL Connection Pattern Detected",
                alert_description_template="Unusual encrypted connection detected from {srcAddr} to {dstAddr}:{dstPort}. Non-standard TLS port usage may indicate encrypted C2 activity.",
                investigation_steps=[
                    "Identify the source instance and its purpose",
                    "Review the destination IP reputation and ownership",
                    "Analyse connection timing and frequency patterns",
                    "Check for legitimate applications using non-standard TLS ports",
                    "Examine TLS certificate details if available",
                    "Review instance processes and installed software",
                    "Check CloudTrail for suspicious API activity from source",
                ],
                containment_actions=[
                    "Block suspicious destination IPs via security groups",
                    "Isolate affected instances from production network",
                    "Enable TLS/SSL inspection using AWS Network Firewall",
                    "Review and restrict outbound internet access",
                    "Deploy endpoint detection and response (EDR) tools",
                    "Capture network traffic for forensic analysis",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate applications using non-standard encrypted ports. Establish baseline for normal encrypted traffic patterns.",
            detection_coverage="70% - detects non-standard TLS but may miss port 443 C2",
            evasion_considerations="Attackers using standard port 443 will evade this detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled", "CloudWatch Logs"],
        ),
        # Strategy 2: AWS - TLS/SSL Certificate Anomalies
        DetectionStrategy(
            strategy_id="t1573-aws-cert-anomaly",
            name="AWS Certificate Manager Certificate Anomaly Detection",
            description="Detect suspicious TLS/SSL certificate requests and unusual certificate configurations that may indicate C2 infrastructure setup.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.acm"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": ["RequestCertificate", "ImportCertificate"]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious TLS certificate operations

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

  # Step 2: EventBridge rule for certificate operations
  CertificateRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Detect TLS certificate requests and imports
      EventPattern:
        source: [aws.acm]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - RequestCertificate
            - ImportCertificate
      State: ENABLED
      Targets:
        - Id: AlertTopic
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
                terraform_template="""# Detect suspicious TLS certificate operations

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "cert_alerts" {
  name = "certificate-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.cert_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for certificate operations
resource "aws_cloudwatch_event_rule" "cert_operations" {
  name        = "certificate-operation-detection"
  description = "Detect TLS certificate requests and imports"

  event_pattern = jsonencode({
    source      = ["aws.acm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "RequestCertificate",
        "ImportCertificate"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.cert_operations.name
  arn  = aws_sns_topic.cert_alerts.arn
}

# Step 3: SNS topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.cert_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.cert_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Suspicious TLS Certificate Operation Detected",
                alert_description_template="TLS certificate {eventName} performed by {userIdentity.principalId}. May indicate C2 infrastructure setup.",
                investigation_steps=[
                    "Identify who requested or imported the certificate",
                    "Review the certificate domain names and validity period",
                    "Check if certificate is for legitimate business use",
                    "Examine recent activities by the principal",
                    "Review IAM permissions for ACM operations",
                    "Check for other suspicious AWS API calls",
                ],
                containment_actions=[
                    "Review and revoke suspicious certificates",
                    "Restrict acm:RequestCertificate and acm:ImportCertificate permissions",
                    "Enable MFA for certificate management operations",
                    "Audit all existing certificates in the account",
                    "Review CloudTrail logs for certificate usage patterns",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Whitelist authorised DevOps and infrastructure teams. Filter legitimate application certificate requests.",
            detection_coverage="50% - detects certificate setup but not usage",
            evasion_considerations="Attackers may use existing certificates or external certificate authorities",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: AWS - Encrypted Traffic to Rare Destinations
        DetectionStrategy(
            strategy_id="t1573-aws-rare-dest",
            name="AWS GuardDuty Encrypted Traffic to Rare Destinations",
            description="Leverage AWS GuardDuty to detect encrypted connections to rarely observed or suspicious destinations.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Backdoor:EC2/C&CActivity.B",
                    "Trojan:EC2/DNSDataExfiltration",
                    "UnauthorizedAccess:EC2/TorClient",
                    "UnauthorizedAccess:EC2/TorRelay",
                    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
                    "Impact:EC2/BitcoinDomainRequest.Reputation",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Configure GuardDuty alerts for encrypted C2 detection

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

  # Step 3: EventBridge rule for encrypted C2 findings
  GuardDutyEncryptedC2Rule:
    Type: AWS::Events::Rule
    Properties:
      Description: Alert on GuardDuty encrypted C2 findings
      EventPattern:
        source: [aws.guardduty]
        detail-type: [GuardDuty Finding]
        detail:
          type:
            - prefix: Backdoor:EC2/C&CActivity
            - prefix: Trojan:EC2/DNSDataExfiltration
            - prefix: UnauthorizedAccess:EC2/Tor
            - prefix: CryptoCurrency:EC2/
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
                terraform_template="""# Configure GuardDuty for encrypted C2 detection

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
  name = "guardduty-encrypted-c2-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: EventBridge rule for encrypted C2 findings
resource "aws_cloudwatch_event_rule" "guardduty_encrypted_c2" {
  name        = "guardduty-encrypted-c2-detection"
  description = "Alert on GuardDuty encrypted C2 findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Backdoor:EC2/C&CActivity" },
        { prefix = "Trojan:EC2/DNSDataExfiltration" },
        { prefix = "UnauthorizedAccess:EC2/Tor" },
        { prefix = "CryptoCurrency:EC2/" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.guardduty_encrypted_c2.name
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
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Encrypted C2 Activity Detected",
                alert_description_template="GuardDuty detected {type} on instance {resource.instanceDetails.instanceId}. This indicates potential encrypted command and control activity.",
                investigation_steps=[
                    "Review GuardDuty finding details and severity",
                    "Identify affected EC2 instances and their roles",
                    "Analyse network connections and destination IPs",
                    "Review CloudTrail logs for suspicious API activity",
                    "Examine VPC Flow Logs for the timeframe",
                    "Check for lateral movement from affected instances",
                    "Investigate any TOR or anonymisation network usage",
                ],
                containment_actions=[
                    "Isolate affected instances immediately",
                    "Create forensic snapshots before remediation",
                    "Revoke instance IAM role credentials",
                    "Block malicious IPs via security groups and NACLs",
                    "Enable AWS Network Firewall for deep packet inspection",
                    "Review and rotate any exposed credentials",
                    "Deploy replacement instances from clean images",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review and suppress findings for legitimate use of TOR or VPNs. Update threat intelligence feed regularly.",
            detection_coverage="90% - GuardDuty uses threat intelligence and ML for high accuracy",
            evasion_considerations="Zero-day C2 infrastructure not in threat intelligence feeds may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$30-100 depending on data volume",
            prerequisites=["GuardDuty enabled", "VPC Flow Logs", "DNS Logs"],
        ),
        # Strategy 4: GCP - Encrypted Connection Anomaly Detection
        DetectionStrategy(
            strategy_id="t1573-gcp-encrypted-anomaly",
            name="GCP VPC Flow Logs Encrypted Traffic Anomaly Detection",
            description="Detect unusual encrypted traffic patterns in GCP VPC Flow Logs including non-standard ports and asymmetric traffic.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName="projects/PROJECT_ID/logs/compute.googleapis.com%2Fvpc_flows"
jsonPayload.connection.dest_port!=443 AND jsonPayload.connection.dest_port!=8443
jsonPayload.connection.protocol=6
jsonPayload.bytes_sent>0
jsonPayload.packets>50""",
                gcp_terraform_template="""# GCP: Detect unusual encrypted connection patterns

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
  display_name = "Security Alerts - Encrypted C2"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for unusual encrypted connections
resource "google_logging_metric" "encrypted_anomaly" {
  name   = "unusual-encrypted-connections"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName=~"projects/.*/logs/compute.googleapis.com%2Fvpc_flows"
    jsonPayload.connection.dest_port!=443
    jsonPayload.connection.dest_port!=8443
    jsonPayload.connection.protocol=6
    jsonPayload.bytes_sent>0
    jsonPayload.packets>50
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "encrypted_c2" {
  display_name = "Unusual Encrypted Connection Detected"
  combiner     = "OR"

  conditions {
    display_name = "Non-standard encrypted traffic pattern"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.encrypted_anomaly.name}\""
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
}""",
                alert_severity="high",
                alert_title="GCP: Unusual Encrypted Connection Pattern Detected",
                alert_description_template="Non-standard encrypted traffic pattern detected in VPC Flow Logs. May indicate encrypted C2 communications.",
                investigation_steps=[
                    "Identify source VM instance and its project",
                    "Review connection patterns and destination IPs",
                    "Check destination IP reputation using threat intelligence",
                    "Analyse Cloud Logging for application-level logs",
                    "Review VM metadata and startup scripts",
                    "Examine TLS/SSL certificate details if available",
                    "Check for unauthorised changes to the instance",
                ],
                containment_actions=[
                    "Isolate affected VM instances using firewall rules",
                    "Create snapshots for forensic analysis",
                    "Revoke service account credentials",
                    "Block malicious IPs via Cloud Armor or VPC firewall",
                    "Enable VPC Service Controls to prevent data exfiltration",
                    "Review IAM permissions for affected resources",
                    "Deploy Cloud IDS for deep packet inspection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Establish baselines for legitimate encrypted traffic patterns. Whitelist known applications using non-standard encrypted ports.",
            detection_coverage="70% - detects non-standard encrypted traffic but may miss port 443 C2",
            evasion_considerations="Attackers using standard HTTPS ports will evade this detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-30",
            prerequisites=["VPC Flow Logs enabled", "Cloud Logging"],
        ),
        # Strategy 5: GCP - Security Command Centre Encrypted Malware Detection
        DetectionStrategy(
            strategy_id="t1573-gcp-scc-encrypted",
            name="GCP Security Command Centre Encrypted Malware Detection",
            description="Leverage Security Command Centre Event Threat Detection to identify encrypted malware communications and C2 activity.",
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
                    "Persistence: IAM Anomalous Grant",
                ],
                gcp_terraform_template="""# GCP: Configure Security Command Centre for encrypted C2 detection

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
  display_name = "Security Alerts - SCC Encrypted C2"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 3: Pub/Sub topic for SCC findings
resource "google_pubsub_topic" "scc_findings" {
  name = "scc-encrypted-c2-findings"
}

resource "google_pubsub_subscription" "scc_findings" {
  name  = "scc-encrypted-c2-findings-sub"
  topic = google_pubsub_topic.scc_findings.name

  ack_deadline_seconds = 20

  push_config {
    push_endpoint = "https://example.com/webhook"  # Replace with your SIEM/SOAR endpoint
  }
}

# Note: SCC notification configs require organisation-level API access
# Configure via: gcloud scc notifications create
# Or use google_scc_notification_config resource with appropriate permissions""",
                alert_severity="critical",
                alert_title="GCP: Encrypted Malware Communication Detected by SCC",
                alert_description_template="Security Command Centre detected {category} on {resourceName}. This indicates potential encrypted C2 activity.",
                investigation_steps=[
                    "Review Security Command Centre finding details",
                    "Identify affected GCP resources and projects",
                    "Check Cloud Audit Logs for suspicious API calls",
                    "Review VPC Flow Logs for network connections",
                    "Analyse VM instance metadata and configurations",
                    "Examine any encrypted traffic patterns",
                    "Check for lateral movement across projects",
                ],
                containment_actions=[
                    "Isolate affected resources immediately",
                    "Create snapshots for forensic investigation",
                    "Revoke compromised service account keys",
                    "Enable VPC Service Controls perimeter",
                    "Block malicious domains and IPs via Cloud Armor",
                    "Review and rotate any exposed credentials",
                    "Apply organisation policy constraints",
                    "Deploy Cloud IDS for network intrusion detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Review findings for legitimate security tools and development environments. Configure SCC muting rules for known benign activities.",
            detection_coverage="85% - SCC uses threat intelligence and behavioural analysis",
            evasion_considerations="Custom or zero-day encrypted C2 infrastructure may not be detected initially",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$50-150 depending on assets",
            prerequisites=[
                "Security Command Centre enabled",
                "Event Threat Detection enabled",
            ],
        ),
        # Strategy 6: AWS - Network Firewall TLS Inspection
        DetectionStrategy(
            strategy_id="t1573-aws-network-firewall",
            name="AWS Network Firewall TLS/SSL Inspection",
            description="Deploy AWS Network Firewall with TLS inspection to identify suspicious encrypted traffic and C2 communications.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="network-firewall",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter event.event_type = "tls"
| filter tls.sni not like /.amazonaws.com$/
| filter tls.sni not like /.microsoft.com$/
| filter tls.sni not like /.google.com$/
| stats count() as connection_count by src_ip, dest_ip, tls.sni
| filter connection_count > 50
| sort connection_count desc
| limit 100""",
                terraform_template="""# Deploy AWS Network Firewall with TLS inspection

variable "vpc_id" {
  type        = string
  description = "VPC ID to protect"
}

variable "subnet_id" {
  type        = string
  description = "Subnet ID for Network Firewall endpoint"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Network Firewall policy with TLS inspection
resource "aws_networkfirewall_firewall_policy" "tls_inspection" {
  name = "tls-inspection-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.encrypted_c2.arn
    }
  }
}

resource "aws_networkfirewall_rule_group" "encrypted_c2" {
  capacity = 100
  name     = "encrypted-c2-detection"
  type     = "STATEFUL"

  rule_group {
    rules_source {
      rules_string = <<-EOT
        alert tls any any -> any any (msg:"Suspicious TLS connection to rare domain"; tls.sni; content:".top"; sid:1000001;)
        alert tls any any -> any any (msg:"TLS connection to known C2 domain"; tls.sni; pcre:"/(tor2web|onion)/"; sid:1000002;)
      EOT
    }
  }
}

# Step 2: CloudWatch Log Group for Network Firewall
resource "aws_cloudwatch_log_group" "network_firewall" {
  name              = "/aws/networkfirewall/tls-inspection"
  retention_in_days = 7
}

# Step 3: Network Firewall
resource "aws_networkfirewall_firewall" "main" {
  name                = "tls-inspection-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.tls_inspection.arn
  vpc_id              = var.vpc_id

  subnet_mapping {
    subnet_id = var.subnet_id
  }
}

resource "aws_networkfirewall_logging_configuration" "main" {
  firewall_arn = aws_networkfirewall_firewall.main.arn

  logging_configuration {
    log_destination_config {
      log_destination = {
        logGroup = aws_cloudwatch_log_group.network_firewall.name
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "ALERT"
    }
  }
}""",
                alert_severity="high",
                alert_title="Network Firewall: Suspicious Encrypted Traffic Detected",
                alert_description_template="AWS Network Firewall detected suspicious TLS traffic from {src_ip} to {dest_ip} ({tls.sni}).",
                investigation_steps=[
                    "Review Network Firewall alert logs",
                    "Identify source instance and application",
                    "Analyse TLS certificate and SNI details",
                    "Check destination domain reputation",
                    "Review recent activities from source instance",
                    "Examine other network connections from source",
                    "Correlate with GuardDuty and CloudTrail events",
                ],
                containment_actions=[
                    "Block suspicious domains via Network Firewall rules",
                    "Isolate affected instances from network",
                    "Update Network Firewall policy to drop suspicious traffic",
                    "Enable enhanced logging and monitoring",
                    "Review and update security group rules",
                    "Deploy additional IDS/IPS capabilities",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist legitimate business domains and applications. Tune TLS inspection rules based on baseline traffic.",
            detection_coverage="85% - deep packet inspection provides high visibility",
            evasion_considerations="Sophisticated attackers may use domain fronting or encrypted tunnels",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$100-300 depending on throughput",
            prerequisites=[
                "VPC with appropriate subnet architecture",
                "CloudWatch Logs",
            ],
        ),
    ],
    recommended_order=[
        "t1573-aws-guardduty",
        "t1573-gcp-scc-encrypted",
        "t1573-aws-tls-anomaly",
        "t1573-gcp-encrypted-anomaly",
        "t1573-aws-network-firewall",
        "t1573-aws-rare-dest",
        "t1573-aws-cert-anomaly",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+30% improvement for Command and Control tactic detection",
)
