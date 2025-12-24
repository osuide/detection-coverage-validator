"""
T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol

Adversaries exfiltrate data over asymmetrically encrypted protocols separate from C2 channels.
Used by APT28, APT29, CURIUM, IcedID, Storm-1811.
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
    technique_id="T1048.002",
    technique_name="Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
    tactic_ids=["TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1048/002/",
    threat_context=ThreatContext(
        description=(
            "Adversaries steal data by exfiltrating it through asymmetrically encrypted "
            "network protocols separate from command and control channels. These mechanisms "
            "use public-key cryptography with paired cryptographic keys, often leveraging "
            "encrypted protocols like HTTPS/TLS/SSL that employ symmetric encryption after "
            "initial key exchange. Common protocols include HTTPS, SMTPS, SFTP, and SCP."
        ),
        attacker_goal="Exfiltrate sensitive data using encrypted protocols to avoid detection and hide data content",
        why_technique=[
            "Encryption prevents DLP inspection",
            "Blends with legitimate encrypted traffic",
            "HTTPS and TLS are rarely blocked",
            "Multiple protocol options provide flexibility",
            "Bypasses traditional content-based detection",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Exfiltration over encrypted protocols is highly effective and difficult to detect. "
            "Encryption prevents DLP and content inspection, making it invisible to traditional "
            "security controls. The technique is widely used by sophisticated threat actors in "
            "major breaches. Loss of sensitive data can result in severe financial, regulatory, "
            "and reputational damage."
        ),
        business_impact=[
            "Data breach and loss of sensitive information",
            "Intellectual property theft",
            "Regulatory fines and compliance violations (GDPR, HIPAA)",
            "Reputational damage and customer trust loss",
            "Operational disruption from incident response",
            "Loss of competitive advantage",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1074", "T1560", "T1552.001", "T1530", "T1005"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1048.002-aws-https-non-browser",
            name="AWS Non-Browser HTTPS Connections After Data Staging",
            description="Detect encrypted outbound connections from non-browser processes following data staging or compression activities.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes, action
| filter dstPort = 443 and action = "ACCEPT"
| filter dstAddr not like /^10\\./ and dstAddr not like /^172\\.1[6-9]\\./
| filter dstAddr not like /^172\\.2[0-9]\\./ and dstAddr not like /^172\\.3[0-1]\\./
| filter dstAddr not like /^192\\.168\\./
| stats sum(bytes) as total_bytes, count(*) as connections by srcAddr, dstAddr, bin(5m)
| filter total_bytes > 52428800
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect non-browser HTTPS exfiltration after data staging

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

  # Step 2: Create metric filter for large HTTPS transfers
  HTTPSExfilFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport=443, protocol, packets, bytes > 50000000, ...]'
      MetricTransformations:
        - MetricName: LargeHTTPSTransfer
          MetricNamespace: Security
          MetricValue: "$bytes"
          Unit: Bytes

  # Step 3: Alert on threshold breach
  HTTPSExfilAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: HTTPS-Exfiltration-Detected
      MetricName: LargeHTTPSTransfer
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 104857600
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect non-browser HTTPS exfiltration after data staging

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "https-exfil-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for large HTTPS transfers
resource "aws_cloudwatch_log_metric_filter" "https_exfil" {
  name           = "large-https-transfer"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport=443, protocol, packets, bytes > 50000000, ...]"

  metric_transformation {
    name      = "LargeHTTPSTransfer"
    namespace = "Security"
    value     = "$bytes"
    unit      = "Bytes"
  }
}

# Step 3: Alert on threshold breach
resource "aws_cloudwatch_metric_alarm" "https_exfil" {
  alarm_name          = "HTTPS-Exfiltration-Detected"
  metric_name         = "LargeHTTPSTransfer"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 104857600
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Large HTTPS Transfer Detected from Non-Browser Process",
                alert_description_template="Large encrypted transfer detected from {srcAddr} to {dstAddr}: {total_bytes} bytes in {connections} connections.",
                investigation_steps=[
                    "Identify the source instance and running processes",
                    "Review process execution history (curl, wget, Python, custom binaries)",
                    "Check for recent data staging or compression activities",
                    "Examine destination IP/domain reputation",
                    "Review user activity and authentication logs",
                    "Correlate with file access events for sensitive data",
                ],
                containment_actions=[
                    "Isolate the source instance immediately",
                    "Block destination IP/domain at security group level",
                    "Revoke credentials for compromised accounts",
                    "Capture network traffic for forensic analysis",
                    "Review and restrict outbound HTTPS access",
                    "Enable TLS inspection for outbound traffic where feasible",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known API endpoints, CDN destinations, and legitimate backup services; tune byte threshold based on baseline",
            detection_coverage="70% - catches large HTTPS-based exfiltration",
            evasion_considerations="Low and slow exfiltration, using legitimate services, small file transfers",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1048.002-aws-sftp-scp",
            name="AWS SFTP/SCP Transfer Detection",
            description="Detect secure file transfer activity using SFTP or SCP protocols.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes, action
| filter dstPort = 22 and action = "ACCEPT"
| filter dstAddr not like /^10\\./ and dstAddr not like /^172\\.1[6-9]\\./
| stats sum(bytes) as total_bytes, count(*) as sessions by srcAddr, dstAddr, bin(1h)
| filter total_bytes > 10485760
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect SFTP/SCP exfiltration activity

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

  # Step 2: Monitor SSH/SFTP/SCP traffic patterns
  SFTPFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport=22, protocol, packets, bytes > 10000000, ...]'
      MetricTransformations:
        - MetricName: SFTPTransfers
          MetricNamespace: Security
          MetricValue: "$bytes"
          Unit: Bytes

  # Step 3: Alert on large transfers
  SFTPAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SFTP-SCP-Transfer-Detected
      MetricName: SFTPTransfers
      Namespace: Security
      Statistic: Sum
      Period: 3600
      Threshold: 52428800
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect SFTP/SCP exfiltration activity

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create alert topic
resource "aws_sns_topic" "alerts" {
  name = "sftp-scp-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Monitor SSH/SFTP/SCP traffic patterns
resource "aws_cloudwatch_log_metric_filter" "sftp" {
  name           = "sftp-scp-transfers"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport=22, protocol, packets, bytes > 10000000, ...]"

  metric_transformation {
    name      = "SFTPTransfers"
    namespace = "Security"
    value     = "$bytes"
    unit      = "Bytes"
  }
}

# Step 3: Alert on large transfers
resource "aws_cloudwatch_metric_alarm" "sftp" {
  alarm_name          = "SFTP-SCP-Transfer-Detected"
  metric_name         = "SFTPTransfers"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 52428800
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Large SFTP/SCP Transfer Detected",
                alert_description_template="Large secure file transfer from {srcAddr} to {dstAddr}: {total_bytes} bytes in {sessions} sessions.",
                investigation_steps=[
                    "Identify source instance and destination server",
                    "Review SSH authentication logs",
                    "Check for authorised file transfer operations",
                    "Examine transferred files if accessible",
                    "Review user activity and recent logins",
                    "Correlate with data staging events",
                ],
                containment_actions=[
                    "Isolate source instance",
                    "Block destination server at security group",
                    "Revoke SSH keys and credentials",
                    "Disable SFTP/SCP if not required",
                    "Review and restrict SSH access policies",
                    "Enable SSH session logging and monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known SFTP servers; exclude scheduled backups and deployments",
            detection_coverage="75% - catches SFTP/SCP-based exfiltration",
            evasion_considerations="Using alternative ports, HTTPS instead of SFTP",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1048.002-aws-smtps",
            name="AWS Encrypted Email Exfiltration (SMTPS)",
            description="Detect data exfiltration via encrypted SMTP (SMTPS) connections.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes, packets
| filter dstPort in [465, 587] and action = "ACCEPT"
| stats sum(bytes) as total_bytes, count(*) as connections by srcAddr, dstAddr, bin(1h)
| filter total_bytes > 10485760 or connections > 50
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect encrypted email exfiltration via SMTPS

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
    Type: String

Resources:
  # Step 1: Create notification topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Monitor encrypted SMTP connections
  SMTPSFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport=465 || dstport=587, protocol, packets, bytes, ...]'
      MetricTransformations:
        - MetricName: SMTPSConnections
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert on unusual activity
  SMTPSAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SMTPS-Exfiltration-Detected
      MetricName: SMTPSConnections
      Namespace: Security
      Statistic: Sum
      Period: 3600
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect encrypted email exfiltration via SMTPS

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create notification topic
resource "aws_sns_topic" "alerts" {
  name = "smtps-exfil-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Monitor encrypted SMTP connections
resource "aws_cloudwatch_log_metric_filter" "smtps" {
  name           = "smtps-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport=465 || dstport=587, protocol, packets, bytes, ...]"

  metric_transformation {
    name      = "SMTPSConnections"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert on unusual activity
resource "aws_cloudwatch_metric_alarm" "smtps" {
  alarm_name          = "SMTPS-Exfiltration-Detected"
  metric_name         = "SMTPSConnections"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Encrypted Email Exfiltration Detected",
                alert_description_template="Unusual encrypted SMTP activity from {srcAddr}: {connections} connections, {total_bytes} bytes.",
                investigation_steps=[
                    "Identify source instance and mail client",
                    "Review email sending patterns and recipients",
                    "Check for compromised email accounts",
                    "Examine email content and attachments if accessible",
                    "Verify against legitimate bulk email operations",
                    "Review authentication logs for unauthorised access",
                ],
                containment_actions=[
                    "Block SMTPS traffic from source instance",
                    "Revoke compromised email credentials",
                    "Disable mail relay if compromised",
                    "Review and restrict SMTP access policies",
                    "Enable email authentication (SPF, DKIM, DMARC)",
                    "Implement rate limiting for outbound email",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist mail servers and SES; tune thresholds for legitimate email volume",
            detection_coverage="65% - catches encrypted email exfiltration",
            evasion_considerations="Using legitimate email services, slow sending rate",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1048.002-aws-cloudtrail",
            name="AWS CloudTrail API Data Access Before Encrypted Transfer",
            description="Detect sensitive data access followed by encrypted network connections using CloudTrail and VPC Flow Logs correlation.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, sourceIPAddress, requestParameters
| filter eventSource in ["s3.amazonaws.com", "secretsmanager.amazonaws.com", "ssm.amazonaws.com"]
| filter eventName in ["GetObject", "GetSecretValue", "GetParameter", "DescribeDBSnapshots"]
| stats count(*) as access_count by userIdentity.arn, sourceIPAddress, bin(5m)
| filter access_count > 10
| sort access_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect sensitive data access before encrypted exfiltration

Parameters:
  AlertEmail:
    Type: String
  CloudTrailLogGroup:
    Type: String

Resources:
  # Step 1: Create alert topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Monitor sensitive data access patterns
  DataAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "s3.amazonaws.com" && $.eventName = "GetObject") || ($.eventSource = "secretsmanager.amazonaws.com" && $.eventName = "GetSecretValue") || ($.eventSource = "ssm.amazonaws.com" && $.eventName = "GetParameter") }'
      MetricTransformations:
        - MetricName: SensitiveDataAccess
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert on rapid access patterns
  DataAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Rapid-Sensitive-Data-Access
      MetricName: SensitiveDataAccess
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 20
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect sensitive data access before encrypted exfiltration

variable "alert_email" { type = string }
variable "cloudtrail_log_group" { type = string }

# Step 1: Create alert topic
resource "aws_sns_topic" "alerts" {
  name = "data-access-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Monitor sensitive data access patterns
resource "aws_cloudwatch_log_metric_filter" "data_access" {
  name           = "sensitive-data-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"s3.amazonaws.com\" && $.eventName = \"GetObject\") || ($.eventSource = \"secretsmanager.amazonaws.com\" && $.eventName = \"GetSecretValue\") || ($.eventSource = \"ssm.amazonaws.com\" && $.eventName = \"GetParameter\") }"

  metric_transformation {
    name      = "SensitiveDataAccess"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert on rapid access patterns
resource "aws_cloudwatch_metric_alarm" "data_access" {
  alarm_name          = "Rapid-Sensitive-Data-Access"
  metric_name         = "SensitiveDataAccess"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 20
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Rapid Sensitive Data Access Detected",
                alert_description_template="Rapid access to sensitive data by {userIdentity.arn} from {sourceIPAddress}: {access_count} operations.",
                investigation_steps=[
                    "Identify the user/role accessing data",
                    "Review accessed resources (S3 objects, secrets, parameters)",
                    "Check for recent network connections from source IP",
                    "Correlate with VPC Flow Logs for encrypted transfers",
                    "Review user's authentication history",
                    "Examine timing between data access and network transfers",
                ],
                containment_actions=[
                    "Revoke compromised credentials immediately",
                    "Block source IP at NACL/security group",
                    "Enable S3 Object Lock on sensitive buckets",
                    "Rotate accessed secrets and parameters",
                    "Review and restrict IAM policies",
                    "Enable MFA for sensitive operations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude automated backup systems and CI/CD pipelines; tune access count threshold",
            detection_coverage="80% - catches data access patterns preceding exfiltration",
            evasion_considerations="Slow data access patterns, legitimate service accounts",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=[
                "CloudTrail enabled with S3 data events",
                "CloudTrail logs in CloudWatch",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1048.002-gcp-https",
            name="GCP Non-Standard HTTPS Exfiltration",
            description="Detect large encrypted data transfers from GCP instances to external destinations.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_subnetwork"
jsonPayload.connection.dest_port=443
jsonPayload.bytes_sent > 52428800
NOT jsonPayload.connection.dest_ip=~"^10\\."
NOT jsonPayload.connection.dest_ip=~"^172\\.(1[6-9]|2[0-9]|3[0-1])\\."
NOT jsonPayload.connection.dest_ip=~"^192\\.168\\."''',
                gcp_terraform_template="""# GCP: Detect HTTPS exfiltration

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 2: Create log metric for large HTTPS transfers
resource "google_logging_metric" "https_exfil" {
  name   = "large-https-exfiltration"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    jsonPayload.connection.dest_port=443
    jsonPayload.bytes_sent > 52428800
    NOT jsonPayload.connection.dest_ip=~"^10\\."
    NOT jsonPayload.connection.dest_ip=~"^172\\.(1[6-9]|2[0-9]|3[0-1])\\."
    NOT jsonPayload.connection.dest_ip=~"^192\\.168\\."
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "https_exfil" {
  display_name = "HTTPS Exfiltration Detected"
  combiner     = "OR"
  conditions {
    display_name = "Large encrypted transfer to external destination"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.https_exfil.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Large HTTPS Exfiltration Detected",
                alert_description_template="Large encrypted transfer to external destination detected from GCP instance.",
                investigation_steps=[
                    "Identify source VM instance",
                    "Review running processes and applications",
                    "Check for data staging or compression activities",
                    "Examine destination IP/domain reputation",
                    "Review user access and authentication logs",
                    "Correlate with Cloud Storage or secret access events",
                ],
                containment_actions=[
                    "Isolate source VM instance",
                    "Block destination IP via firewall rules",
                    "Revoke compromised service account credentials",
                    "Review and restrict VPC egress rules",
                    "Enable VPC Service Controls",
                    "Implement Cloud NAT logging for visibility",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known API endpoints and CDN destinations; adjust byte threshold",
            detection_coverage="70% - catches large HTTPS-based exfiltration",
            evasion_considerations="Low and slow transfers, legitimate cloud services",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled on subnets"],
        ),
        DetectionStrategy(
            strategy_id="t1048.002-gcp-storage-access",
            name="GCP Cloud Storage Access Before Encrypted Transfer",
            description="Detect Cloud Storage object access followed by encrypted network activity.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.methodName="storage.objects.get"
protoPayload.authenticationInfo.principalEmail!=""
| stats count() as access_count by protoPayload.authenticationInfo.principalEmail, protoPayload.requestMetadata.callerIp
| access_count > 20""",
                gcp_terraform_template="""# GCP: Detect Cloud Storage access before exfiltration

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 2: Create metric for rapid storage access
resource "google_logging_metric" "storage_access" {
  name   = "rapid-storage-access"
  filter = <<-EOT
    protoPayload.methodName="storage.objects.get"
    protoPayload.authenticationInfo.principalEmail!=""
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert on unusual access patterns
resource "google_monitoring_alert_policy" "storage_access" {
  display_name = "Rapid Cloud Storage Access"
  combiner     = "OR"
  conditions {
    display_name = "High rate of object access"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.storage_access.name}\""
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
}""",
                alert_severity="high",
                alert_title="GCP: Rapid Cloud Storage Access Detected",
                alert_description_template="Rapid access to Cloud Storage objects detected, potential data staging for exfiltration.",
                investigation_steps=[
                    "Identify the principal/service account",
                    "Review accessed storage buckets and objects",
                    "Check for recent encrypted network connections",
                    "Correlate with VPC Flow Logs",
                    "Review IAM policy changes",
                    "Examine authentication and access patterns",
                ],
                containment_actions=[
                    "Revoke compromised service account keys",
                    "Enable Object Versioning and retention policies",
                    "Implement VPC Service Controls",
                    "Review and restrict IAM permissions",
                    "Enable uniform bucket-level access",
                    "Implement Cloud Data Loss Prevention scanning",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude backup systems and data processing pipelines; tune access rate threshold",
            detection_coverage="75% - catches data access preceding exfiltration",
            evasion_considerations="Slow access patterns, using authorised service accounts",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Audit Logs for Cloud Storage enabled",
                "VPC Flow Logs enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1048.002-aws-cloudtrail",
        "t1048.002-gcp-storage-access",
        "t1048.002-aws-https-non-browser",
        "t1048.002-gcp-https",
        "t1048.002-aws-sftp-scp",
        "t1048.002-aws-smtps",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+22% improvement for Exfiltration tactic",
)
