"""
T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol

Adversaries exfiltrate data over symmetrically encrypted protocols separate from C2.
Used by OilRig, APT41, FIN6, Turla.
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
    technique_id="T1048.001",
    technique_name="Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
    tactic_ids=["TA0010"],
    mitre_url="https://attack.mitre.org/techniques/T1048/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries steal data by exfiltrating it over a symmetrically encrypted network "
            "protocol other than that of the existing command and control channel. Symmetric "
            "encryption algorithms use shared or identical keys/secrets on each end of the channel. "
            "Adversaries may manually implement symmetric cryptographic algorithms (such as RC4, AES) "
            "instead of using mechanisms built into protocols. This can create multiple layers of "
            "encryption (in protocols that are natively encrypted such as HTTPS) or add encryption "
            "to protocols not typically encrypted (such as HTTP or FTP)."
        ),
        attacker_goal="Exfiltrate data using custom symmetric encryption to hide content and evade detection",
        why_technique=[
            "Bypasses DLP and content inspection",
            "Multiple encryption layers hide data",
            "Custom encryption evades signatures",
            "Separate from C2 avoids correlation",
            "Blends with legitimate encrypted traffic",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Symmetric encryption of exfiltration traffic is extremely difficult to detect as "
            "it bypasses traditional DLP and content inspection tools. Custom encryption implementations "
            "evade signature-based detection. Loss of sensitive data can result in severe financial, "
            "regulatory, and reputational damage. The separation from C2 channels makes correlation "
            "and detection significantly more challenging."
        ),
        business_impact=[
            "Data breach and loss of sensitive information",
            "Intellectual property theft",
            "Regulatory fines and compliance violations",
            "Reputational damage and customer trust loss",
            "Bypasses of DLP investments",
        ],
        typical_attack_phase="exfiltration",
        often_precedes=[],
        often_follows=["T1530", "T1552.001", "T1005", "T1074", "T1560"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1048.001-aws-encrypted-non-browser",
            name="AWS Non-Browser Encrypted Connections",
            description="Detect non-browser processes establishing outbound encrypted connections using uncommon symmetric encryption.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcAddr, dstAddr, dstPort, bytes, protocol
| filter dstPort in [443, 8443, 9443] and action = "ACCEPT"
| stats sum(bytes) as total_bytes, count(*) as connection_count by srcAddr, dstAddr, dstPort, bin(5m)
| filter total_bytes > 52428800 or connection_count > 100
| sort total_bytes desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect non-browser encrypted connections for exfiltration

Parameters:
  AlertEmail:
    Type: String
  VPCFlowLogGroup:
    Type: String

Resources:
  # Step 1: Create SNS alert topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Filter for encrypted traffic patterns
  EncryptedTrafficFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, dstport=443 || dstport=8443 || dstport=9443, protocol, packets, bytes > 50000000, ...]'
      MetricTransformations:
        - MetricName: EncryptedExfilTraffic
          MetricNamespace: Security
          MetricValue: "$bytes"
          Unit: Bytes

  # Step 3: Alert on unusual encrypted transfers
  EncryptedExfilAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Encrypted-Exfiltration-Detected
      MetricName: EncryptedExfilTraffic
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
                terraform_template="""# Detect non-browser encrypted connections for exfiltration

variable "alert_email" { type = string }
variable "vpc_flow_log_group" { type = string }

# Step 1: Create SNS alert topic
resource "aws_sns_topic" "alerts" {
  name = "encrypted-exfil-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Filter for encrypted traffic patterns
resource "aws_cloudwatch_log_metric_filter" "encrypted_traffic" {
  name           = "encrypted-exfil-traffic"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, dstport=443 || dstport=8443 || dstport=9443, protocol, packets, bytes > 50000000, ...]"

  metric_transformation {
    name      = "EncryptedExfilTraffic"
    namespace = "Security"
    value     = "$bytes"
    unit      = "Bytes"
  }
}

# Step 3: Alert on unusual encrypted transfers
resource "aws_cloudwatch_metric_alarm" "encrypted_exfil" {
  alarm_name          = "Encrypted-Exfiltration-Detected"
  metric_name         = "EncryptedExfilTraffic"
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
                alert_title="Encrypted Exfiltration Detected",
                alert_description_template="Large encrypted transfer from {srcAddr} to {dstAddr}:{dstPort} - {total_bytes} bytes transferred.",
                investigation_steps=[
                    "Identify the source instance and process",
                    "Analyse encryption libraries or tools in use",
                    "Review destination IP reputation",
                    "Check for OpenSSL, GPG, or custom crypto usage",
                    "Correlate with file staging activity",
                    "Examine process execution history",
                ],
                containment_actions=[
                    "Isolate the source instance",
                    "Block destination IP at security group",
                    "Review and restrict outbound HTTPS traffic",
                    "Capture network traffic for forensic analysis",
                    "Disable suspicious processes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup services and CDN endpoints; adjust byte thresholds for environment",
            detection_coverage="60% - catches large encrypted transfers",
            evasion_considerations="Low and slow exfiltration, using legitimate services",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1048.001-aws-crypto-tools",
            name="AWS Encryption Tool Usage",
            description="Detect command-line utilities and scripts leveraging encryption libraries with external file transfers.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters, responseElements
| filter eventSource = "cloudtrail.amazonaws.com"
| filter eventName in ["RunInstances", "StartInstances"]
| filter requestParameters.userData like /openssl|gpg|aes|rc4|pycrypto|cryptography/
| stats count() as exec_count by userIdentity.arn, requestParameters.instanceType
| sort exec_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect encryption tool usage for exfiltration

Parameters:
  AlertEmail:
    Type: String
  CloudTrailLogGroup:
    Type: String

Resources:
  # Step 1: Create SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Filter for encryption tool execution
  CryptoToolFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "RunInstances" || $.eventName = "StartInstances") && ($.requestParameters.userData = "*openssl*" || $.requestParameters.userData = "*gpg*" || $.requestParameters.userData = "*aes*" || $.requestParameters.userData = "*pycrypto*") }'
      MetricTransformations:
        - MetricName: CryptoToolExecution
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert on crypto tool usage
  CryptoToolAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: Encryption-Tool-Detected
      MetricName: CryptoToolExecution
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 1
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
                terraform_template="""# Detect encryption tool usage for exfiltration

variable "alert_email" { type = string }
variable "cloudtrail_log_group" { type = string }

# Step 1: Create SNS topic
resource "aws_sns_topic" "alerts" {
  name = "crypto-tool-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Filter for encryption tool execution
resource "aws_cloudwatch_log_metric_filter" "crypto_tool" {
  name           = "crypto-tool-execution"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"RunInstances\" || $.eventName = \"StartInstances\") && ($.requestParameters.userData = \"*openssl*\" || $.requestParameters.userData = \"*gpg*\" || $.requestParameters.userData = \"*aes*\" || $.requestParameters.userData = \"*pycrypto*\") }"

  metric_transformation {
    name      = "CryptoToolExecution"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert on crypto tool usage
resource "aws_cloudwatch_metric_alarm" "crypto_tool" {
  alarm_name          = "Encryption-Tool-Detected"
  metric_name         = "CryptoToolExecution"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
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
                alert_title="Encryption Tool Usage Detected",
                alert_description_template="Encryption tool executed by {userIdentity.arn} on instance.",
                investigation_steps=[
                    "Review the user data or script executed",
                    "Identify encryption library and algorithm used",
                    "Check for data staging or collection activity",
                    "Review network connections from instance",
                    "Examine command history and process tree",
                    "Verify business justification for encryption",
                ],
                containment_actions=[
                    "Terminate suspicious instances",
                    "Revoke user credentials",
                    "Block outbound connections",
                    "Review and restrict IAM permissions",
                    "Enable enhanced monitoring",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised encryption use cases (e.g., database encryption, backup systems)",
            detection_coverage="50% - catches explicit crypto tool usage",
            evasion_considerations="Pre-installed tools, custom implementations, obfuscated commands",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled with data events"],
        ),
        DetectionStrategy(
            strategy_id="t1048.001-aws-symmetric-key-ops",
            name="AWS Symmetric Key Operations",
            description="Detect symmetric key encryption operations followed by unusual outbound connections.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.keyId, errorCode
| filter eventSource = "kms.amazonaws.com"
| filter eventName in ["Encrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext"]
| filter errorCode not exists or errorCode = ""
| stats count() as encrypt_ops by userIdentity.arn, requestParameters.keyId, bin(5m)
| filter encrypt_ops > 50
| sort encrypt_ops desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect symmetric key operations for potential exfiltration

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

  # Step 2: Monitor KMS symmetric encryption operations
  KMSEncryptionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "kms.amazonaws.com" && ($.eventName = "Encrypt" || $.eventName = "GenerateDataKey") && $.errorCode NOT EXISTS }'
      MetricTransformations:
        - MetricName: SymmetricEncryptionOps
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert on high-volume encryption
  SymmetricEncryptAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: High-Symmetric-Encryption-Activity
      MetricName: SymmetricEncryptionOps
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
                terraform_template="""# Detect symmetric key operations for potential exfiltration

variable "alert_email" { type = string }
variable "cloudtrail_log_group" { type = string }

# Step 1: Create alert topic
resource "aws_sns_topic" "alerts" {
  name = "symmetric-encryption-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Monitor KMS symmetric encryption operations
resource "aws_cloudwatch_log_metric_filter" "kms_encryption" {
  name           = "symmetric-encryption-ops"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"kms.amazonaws.com\" && ($.eventName = \"Encrypt\" || $.eventName = \"GenerateDataKey\") && $.errorCode NOT EXISTS }"

  metric_transformation {
    name      = "SymmetricEncryptionOps"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert on high-volume encryption
resource "aws_cloudwatch_metric_alarm" "symmetric_encrypt" {
  alarm_name          = "High-Symmetric-Encryption-Activity"
  metric_name         = "SymmetricEncryptionOps"
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
                alert_severity="medium",
                alert_title="High Symmetric Encryption Activity",
                alert_description_template="Unusual volume of symmetric encryption operations by {userIdentity.arn} - {encrypt_ops} operations.",
                investigation_steps=[
                    "Identify the principal performing encryption",
                    "Review KMS key usage patterns",
                    "Check for concurrent outbound network activity",
                    "Examine encrypted data destinations",
                    "Verify legitimate encryption use cases",
                    "Review CloudTrail for data access patterns",
                ],
                containment_actions=[
                    "Disable suspicious KMS keys",
                    "Revoke IAM permissions for encryption",
                    "Enable KMS key rotation",
                    "Review and restrict key policies",
                    "Isolate systems performing encryption",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal encryption volumes; exclude batch processing jobs and ETL workloads",
            detection_coverage="55% - catches KMS-based encryption",
            evasion_considerations="Using client-side encryption libraries, non-KMS encryption",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["CloudTrail with KMS data events enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1048.001-gcp-encrypted-egress",
            name="GCP Encrypted Egress Detection",
            description="Detect unexpected encrypted egress traffic using symmetric encryption without traditional protocols.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
jsonPayload.connection.dest_port:(443 OR 8443 OR 9443)
jsonPayload.bytes_sent > 52428800
NOT jsonPayload.dest_ip:(35.0.0.0/8 OR 34.0.0.0/8)""",
                gcp_terraform_template="""# GCP: Encrypted egress detection

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Enable VPC Flow Logs on subnet (assuming existing VPC)
# Note: Flow logs are configured per subnet in GCP

# Step 2: Create metric for encrypted egress
resource "google_logging_metric" "encrypted_egress" {
  project = var.project_id
  name   = "encrypted-egress-traffic"
  filter = <<-EOT
    resource.type="gce_instance"
    (jsonPayload.connection.dest_port=443 OR
     jsonPayload.connection.dest_port=8443 OR
     jsonPayload.connection.dest_port=9443)
    jsonPayload.bytes_sent > 52428800
    NOT jsonPayload.dest_ip:(35.0.0.0/8 OR 34.0.0.0/8)
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

resource "google_monitoring_alert_policy" "encrypted_egress" {
  project      = var.project_id
  display_name = "Encrypted Exfiltration Detected"
  combiner     = "OR"
  conditions {
    display_name = "Large encrypted egress transfer"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.encrypted_egress.name}\""
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
                alert_title="GCP: Encrypted Exfiltration Detected",
                alert_description_template="Large encrypted transfer detected from GCP instance to external destination.",
                investigation_steps=[
                    "Identify source compute instance",
                    "Review destination IP and domain reputation",
                    "Analyse encryption tools or libraries in use",
                    "Check for data staging activity",
                    "Examine instance metadata and startup scripts",
                    "Review VPC firewall rules",
                ],
                containment_actions=[
                    "Isolate the source instance",
                    "Block destination via VPC firewall",
                    "Review and restrict egress rules",
                    "Snapshot instance for forensics",
                    "Revoke service account permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known backup destinations and Google Cloud IPs; adjust byte thresholds",
            detection_coverage="60% - catches large encrypted transfers",
            evasion_considerations="Low and slow exfiltration, using GCP services",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$15-30",
            prerequisites=["VPC Flow Logs enabled on subnets"],
        ),
        DetectionStrategy(
            strategy_id="t1048.001-gcp-crypto-activity",
            name="GCP Cryptographic Activity Monitoring",
            description="Detect cryptographic operations and library usage indicative of custom encryption.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
(protoPayload.request.metadata.items.value=~".*openssl.*" OR
 protoPayload.request.metadata.items.value=~".*gpg.*" OR
 protoPayload.request.metadata.items.value=~".*aes.*" OR
 protoPayload.request.metadata.items.value=~".*pycrypto.*")
protoPayload.methodName="v1.compute.instances.insert"''',
                gcp_terraform_template="""# GCP: Cryptographic activity monitoring

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create log metric for crypto tool usage
resource "google_logging_metric" "crypto_tools" {
  project = var.project_id
  name   = "crypto-tool-usage"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName="v1.compute.instances.insert"
    (protoPayload.request.metadata.items.value=~".*openssl.*" OR
     protoPayload.request.metadata.items.value=~".*gpg.*" OR
     protoPayload.request.metadata.items.value=~".*aes.*" OR
     protoPayload.request.metadata.items.value=~".*pycrypto.*")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 2: Create notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Security Alerts"
  type         = "email"
  labels       = { email_address = var.alert_email }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "crypto_tools" {
  project      = var.project_id
  display_name = "Encryption Tool Usage Detected"
  combiner     = "OR"
  conditions {
    display_name = "Crypto tool execution"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.crypto_tools.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
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
                alert_title="GCP: Encryption Tool Usage Detected",
                alert_description_template="Encryption tool or library detected in instance startup.",
                investigation_steps=[
                    "Review instance startup scripts and metadata",
                    "Identify encryption libraries or tools used",
                    "Check for data access or collection activity",
                    "Analyse network connections from instance",
                    "Review service account permissions",
                    "Verify business justification",
                ],
                containment_actions=[
                    "Stop suspicious instances",
                    "Delete unauthorised startup scripts",
                    "Revoke service account credentials",
                    "Review and restrict IAM permissions",
                    "Enable OS Config for compliance",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised encryption use cases (e.g., application encryption, secure storage)",
            detection_coverage="50% - catches explicit crypto tool usage in instance creation",
            evasion_considerations="Pre-built images with tools, runtime installation, obfuscation",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled for Compute Engine"],
        ),
        # Azure Strategy: Exfiltration Over Symmetric Encrypted Non-C2 Protocol
        DetectionStrategy(
            strategy_id="t1048001-azure",
            name="Azure Exfiltration Over Symmetric Encrypted Non-C2 Protocol Detection",
            description=(
                "Azure detection for Exfiltration Over Symmetric Encrypted Non-C2 Protocol. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.LOG_ANALYTICS_QUERY,
            aws_service="n/a",
            azure_service="log_analytics",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                azure_kql_query="""// Exfiltration Over Symmetric Encrypted Non-C2 Protocol Detection
// Technique: T1048.001
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc""",
                azure_terraform_template="""# Azure Detection for Exfiltration Over Symmetric Encrypted Non-C2 Protocol
# MITRE ATT&CK: T1048.001

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

# Action Group for alerts
resource "azurerm_monitor_action_group" "security_alerts" {
  name                = "exfiltration-over-symmetric-encrypted-non-c2-proto-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Scheduled Query Rule for detection
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  name                = "exfiltration-over-symmetric-encrypted-non-c2-proto-detection"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 2

  criteria {
    query = <<-QUERY
// Exfiltration Over Symmetric Encrypted Non-C2 Protocol Detection
// Technique: T1048.001
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue == "Administrative"
| where ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded"
| summarize
    OperationCount = count(),
    UniqueCallers = dcount(Caller),
    Resources = make_set(Resource, 10)
    by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where OperationCount > 10
| order by OperationCount desc
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

  action {
    action_groups = [azurerm_monitor_action_group.security_alerts.id]
  }

  description = "Detects Exfiltration Over Symmetric Encrypted Non-C2 Protocol (T1048.001) activity in Azure environment"
  display_name = "Exfiltration Over Symmetric Encrypted Non-C2 Protocol Detection"
  enabled      = true

  tags = {
    "mitre-technique" = "T1048.001"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Exfiltration Over Symmetric Encrypted Non-C2 Protocol Detected",
                alert_description_template=(
                    "Exfiltration Over Symmetric Encrypted Non-C2 Protocol activity detected. "
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
        "t1048.001-aws-encrypted-non-browser",
        "t1048.001-gcp-encrypted-egress",
        "t1048.001-aws-crypto-tools",
        "t1048.001-gcp-crypto-activity",
        "t1048.001-aws-symmetric-key-ops",
    ],
    total_effort_hours=7.0,
    coverage_improvement="+15% improvement for Exfiltration tactic",
)
