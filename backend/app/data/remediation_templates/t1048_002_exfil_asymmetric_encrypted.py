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
      KmsMasterKeyId: alias/aws/sns
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
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

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
                terraform_template="""# Detect non-browser HTTPS exfiltration after data staging

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "https-exfil-alerts"
  kms_master_key_id = "alias/aws/sns"
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
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
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
      KmsMasterKeyId: alias/aws/sns
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
      Period: 300
      Threshold: 52428800
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

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
                terraform_template="""# Detect SFTP/SCP exfiltration activity

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create alert topic
resource "aws_sns_topic" "alerts" {
  name = "sftp-scp-alerts"
  kms_master_key_id = "alias/aws/sns"
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
  period              = 300
  threshold           = 52428800
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
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
      KmsMasterKeyId: alias/aws/sns
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
      Period: 300
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

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
                terraform_template="""# Detect encrypted email exfiltration via SMTPS

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create notification topic
resource "aws_sns_topic" "alerts" {
  name = "smtps-exfil-alerts"
  kms_master_key_id = "alias/aws/sns"
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
  period              = 300
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
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
      KmsMasterKeyId: alias/aws/sns
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
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]

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
                terraform_template="""# Detect sensitive data access before encrypted exfiltration

variable "alert_email" { type = string }
variable "cloudtrail_log_group" { type = string }

# Step 1: Create alert topic
resource "aws_sns_topic" "alerts" {
  name = "data-access-alerts"
  kms_master_key_id = "alias/aws/sns"
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
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
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
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 2: Create log metric for large HTTPS transfers
resource "google_logging_metric" "https_exfil" {
  project = var.project_id
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
  project      = var.project_id
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
  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
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
protoPayload.authenticationInfo.principalEmail!=""" "",
                gcp_terraform_template="""# GCP: Detect Cloud Storage access before exfiltration

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 2: Create metric for rapid storage access
resource "google_logging_metric" "storage_access" {
  project = var.project_id
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
  project      = var.project_id
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
  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
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
        # Azure Strategy: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
        DetectionStrategy(
            strategy_id="t1048002-azure",
            name="Azure Exfiltration Over Asymmetric Encrypted Non-C2 Protocol Detection",
            description=(
                "Azure detection for Exfiltration Over Asymmetric Encrypted Non-C2 Protocol. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Exfiltration Over Asymmetric Encrypted Non-C2 Protocol Detection
// Technique: T1048.002
// Detects HTTPS/TLS exfiltration, SFTP, and asymmetric key operations
// Prerequisites: AzureNetworkAnalytics_CL, AzureDiagnostics (Key Vault)

// Large HTTPS Egress to External Destinations
let HTTPSExfiltration = AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where DestPort_d == 443  // HTTPS
| where FlowDirection_s == "O"  // Outbound
| where FlowStatus_s == "A"  // Allowed
| where FlowType_s in ("ExternalPublic", "ExternalVirtual")
// Exclude known Azure and Microsoft IPs
| where not(DestIP_s startswith "13." or DestIP_s startswith "20." or DestIP_s startswith "40.")
| summarize
    TotalBytes = sum(todouble(OutboundBytes_d)),
    Connections = count(),
    UniqueDestinations = dcount(DestIP_s),
    TopDestinations = make_set(DestIP_s, 10)
    by SrcIP_s, bin(TimeGenerated, 1h)
| where TotalBytes > 52428800  // > 50 MB
| extend AlertType = "LargeHTTPSEgress";

// SFTP/SCP Exfiltration (SSH port 22)
let SFTPExfiltration = AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where DestPort_d == 22  // SSH/SFTP
| where FlowDirection_s == "O"
| where FlowStatus_s == "A"
| where FlowType_s in ("ExternalPublic", "ExternalVirtual")
| summarize
    TotalBytes = sum(todouble(OutboundBytes_d)),
    Sessions = count(),
    UniqueServers = dcount(DestIP_s)
    by SrcIP_s, bin(TimeGenerated, 1h)
| where TotalBytes > 10485760  // > 10 MB
| extend AlertType = "SFTPExfiltration";

// SMTPS (Encrypted Email) Exfiltration
let SMTPSExfiltration = AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where DestPort_d in (465, 587, 993, 995)  // SMTPS, Submission, IMAPS, POP3S
| where FlowDirection_s == "O"
| where FlowStatus_s == "A"
| where FlowType_s in ("ExternalPublic", "ExternalVirtual")
| summarize
    TotalBytes = sum(todouble(OutboundBytes_d)),
    EmailConnections = count(),
    UniqueMailServers = dcount(DestIP_s)
    by SrcIP_s, bin(TimeGenerated, 1h)
| where TotalBytes > 10485760 or EmailConnections > 100
| extend AlertType = "EncryptedEmailExfiltration";

// Asymmetric Key Operations in Key Vault (RSA, EC)
let AsymmetricKeyOps = AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in (
    "KeySign",           // Using private key to sign (for auth/exfil)
    "KeyVerify",         // Verifying signatures
    "KeyEncrypt",        // RSA encryption
    "KeyDecrypt",        // RSA decryption
    "CertificateGet",    // Getting certificate (for TLS)
    "CertificateImport"  // Importing cert (for exfil channel)
)
| where ResultSignature == "OK" or ResultSignature == "200"
| summarize
    AsymmetricOps = count(),
    UniqueKeys = dcount(id_s),
    Operations = make_set(OperationName, 10)
    by CallerIPAddress, identity_claim_upn_s, bin(TimeGenerated, 1h)
| where AsymmetricOps > 10
| extend AlertType = "HighAsymmetricKeyUsage";

// Sensitive Data Access Followed by Encrypted Transfer (correlation)
let DataAccessBeforeTransfer = AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has_any (
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    "Microsoft.KeyVault/vaults/secrets/read",
    "Microsoft.Sql/servers/databases/export"
)
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    DataAccessOps = count(),
    ResourcesAccessed = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 30m)
| where DataAccessOps > 5
| extend AlertType = "BulkDataAccessBeforeTransfer";

// Combine all detection signals
HTTPSExfiltration
| union SFTPExfiltration
| union SMTPSExfiltration
| union AsymmetricKeyOps
| union DataAccessBeforeTransfer
| project
    TimeGenerated,
    AlertType,
    SourceIP = coalesce(SrcIP_s, CallerIPAddress, CallerIpAddress),
    User = coalesce(identity_claim_upn_s, Caller),
    Details = pack_all()
| order by TimeGenerated desc""",
                azure_terraform_template="""# Azure Detection for Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
# MITRE ATT&CK: T1048.002

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
  name                = "t1048-002-asymmetric-encrypted-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "T1048002"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Alert 1: Large HTTPS Egress to External Destinations
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "https_exfiltration" {
  name                = "t1048-002-https-exfiltration"
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
| where DestPort_d == 443
| where FlowDirection_s == "O"
| where FlowStatus_s == "A"
| where FlowType_s in ("ExternalPublic", "ExternalVirtual")
| where not(DestIP_s startswith "13." or DestIP_s startswith "20." or DestIP_s startswith "40.")
| summarize
    TotalBytes = sum(todouble(OutboundBytes_d)),
    Connections = count(),
    UniqueDestinations = dcount(DestIP_s)
    by SrcIP_s, bin(TimeGenerated, 1h)
| where TotalBytes > 52428800
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
  description  = "Detects large HTTPS egress (>50MB) to non-Azure destinations (T1048.002)"
  display_name = "Large HTTPS Exfiltration Detected"
  enabled      = true
  tags         = { "mitre-technique" = "T1048.002", "detection-type" = "security" }
}

# Alert 2: SFTP/SCP Exfiltration
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "sftp_exfiltration" {
  name                = "t1048-002-sftp-exfiltration"
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
| where DestPort_d == 22
| where FlowDirection_s == "O"
| where FlowStatus_s == "A"
| where FlowType_s in ("ExternalPublic", "ExternalVirtual")
| summarize
    TotalBytes = sum(todouble(OutboundBytes_d)),
    Sessions = count(),
    UniqueServers = dcount(DestIP_s)
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
  description  = "Detects large SFTP/SCP transfers (>10MB) to external servers (T1048.002)"
  display_name = "SFTP Exfiltration Detected"
  enabled      = true
  tags         = { "mitre-technique" = "T1048.002", "detection-type" = "security" }
}

# Alert 3: SMTPS (Encrypted Email) Exfiltration
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "smtps_exfiltration" {
  name                = "t1048-002-smtps-exfiltration"
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
| where DestPort_d in (465, 587, 993, 995)
| where FlowDirection_s == "O"
| where FlowStatus_s == "A"
| where FlowType_s in ("ExternalPublic", "ExternalVirtual")
| summarize
    TotalBytes = sum(todouble(OutboundBytes_d)),
    EmailConnections = count(),
    UniqueMailServers = dcount(DestIP_s)
    by SrcIP_s, bin(TimeGenerated, 1h)
| where TotalBytes > 10485760 or EmailConnections > 100
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
  description  = "Detects high volume encrypted email exfiltration (T1048.002)"
  display_name = "Encrypted Email Exfiltration Detected"
  enabled      = true
  tags         = { "mitre-technique" = "T1048.002", "detection-type" = "security" }
}

# Alert 4: Asymmetric Key Operations in Key Vault
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "asymmetric_key_ops" {
  name                = "t1048-002-asymmetric-key-ops"
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
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("KeySign", "KeyVerify", "KeyEncrypt", "KeyDecrypt", "CertificateGet", "CertificateImport")
| where ResultSignature == "OK" or ResultSignature == "200"
| summarize
    AsymmetricOps = count(),
    UniqueKeys = dcount(id_s),
    Operations = make_set(OperationName, 10)
    by CallerIPAddress, identity_claim_upn_s, bin(TimeGenerated, 1h)
| where AsymmetricOps > 10
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
  description  = "Detects high-volume asymmetric key operations in Azure Key Vault (T1048.002)"
  display_name = "High Asymmetric Key Usage Detected"
  enabled      = true
  tags         = { "mitre-technique" = "T1048.002", "detection-type" = "security" }
}

# Alert 5: Bulk Data Access Before Transfer
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "bulk_data_access" {
  name                = "t1048-002-bulk-data-access"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT30M"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
AzureActivity
| where TimeGenerated > ago(30m)
| where OperationNameValue has_any (
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    "Microsoft.KeyVault/vaults/secrets/read",
    "Microsoft.Sql/servers/databases/export"
)
| where ActivityStatusValue in ("Success", "Succeeded")
| summarize
    DataAccessOps = count(),
    ResourcesAccessed = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 30m)
| where DataAccessOps > 5
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
  description  = "Detects bulk data access that may precede encrypted exfiltration (T1048.002)"
  display_name = "Bulk Data Access Before Transfer"
  enabled      = true
  tags         = { "mitre-technique" = "T1048.002", "detection-type" = "security" }
}

output "alert_rule_ids" {
  value = {
    https_exfiltration  = azurerm_monitor_scheduled_query_rules_alert_v2.https_exfiltration.id
    sftp_exfiltration   = azurerm_monitor_scheduled_query_rules_alert_v2.sftp_exfiltration.id
    smtps_exfiltration  = azurerm_monitor_scheduled_query_rules_alert_v2.smtps_exfiltration.id
    asymmetric_key_ops  = azurerm_monitor_scheduled_query_rules_alert_v2.asymmetric_key_ops.id
    bulk_data_access    = azurerm_monitor_scheduled_query_rules_alert_v2.bulk_data_access.id
  }
}""",
                alert_severity="high",
                alert_title="Azure: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol Detected",
                alert_description_template=(
                    "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol activity detected. "
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
