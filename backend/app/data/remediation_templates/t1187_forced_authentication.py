"""
T1187 - Forced Authentication

Adversaries may gather credential material by invoking or forcing a user to
automatically provide authentication information through a mechanism in which
they can intercept.
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
    technique_id="T1187",
    technique_name="Forced Authentication",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1187/",
    threat_context=ThreatContext(
        description=(
            "Adversaries may gather credential material by invoking or forcing a user to "
            "automatically provide authentication information through a mechanism in which "
            "they can intercept. This technique primarily targets Windows environments "
            "through SMB, WebDAV, or EFSRPC protocols, but similar credential harvesting "
            "tactics can be adapted to cloud environments through phishing, OAuth abuse, "
            "and metadata service exploitation."
        ),
        attacker_goal="Harvest user credentials or authentication tokens by forcing automatic authentication attempts",
        why_technique=[
            "Exploits inherent system behaviour that automatically sends credentials",
            "User interaction may be minimal or invisible",
            "Can capture NTLM hashes without user awareness",
            "Difficult for users to distinguish malicious from legitimate authentication prompts",
            "In cloud environments, can abuse OAuth flows and metadata services",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Forced authentication attacks are effective because they exploit inherent system "
            "behaviour rather than vulnerabilities. While primarily a Windows technique, "
            "similar tactics in cloud environments (OAuth phishing, metadata exploitation) "
            "can lead to credential compromise. Success provides attackers with credential "
            "material that can be cracked offline or relayed to gain unauthorised access."
        ),
        business_impact=[
            "Credential compromise enabling lateral movement",
            "Offline password cracking of captured hashes",
            "NTLM relay attacks leading to privilege escalation",
            "OAuth token theft enabling cloud account takeover",
            "Loss of sensitive authentication material",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1550", "T1078", "T1021"],
        often_follows=["T1566", "T1204"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Unusual Outbound SMB/Authentication Traffic
        DetectionStrategy(
            strategy_id="t1187-aws-network",
            name="Detect Unusual Outbound Authentication Attempts",
            description=(
                "Monitor VPC Flow Logs and GuardDuty for unusual outbound connections "
                "on authentication-related ports (SMB 139/445, WebDAV 80/443) that may "
                "indicate forced authentication attempts from compromised EC2 instances."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Behavior:EC2/NetworkPortUnusual",
                    "Behavior:EC2/TrafficVolumeUnusual",
                    "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor for unusual outbound authentication traffic

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty (monitors unusual network behaviour)
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true

  # Step 2: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Create DLQ for reliability
  DLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: forced-auth-network-alerts-dlq
      MessageRetentionPeriod: 1209600

  NetworkFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Behavior:EC2/NetworkPortUnusual"
            - prefix: "Behavior:EC2/TrafficVolumeUnusual"
      Targets:
        - Id: Email
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAgeInSeconds: 3600
          DeadLetterConfig:
            Arn: !GetAtt DLQ.Arn

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublish
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt NetworkFindingsRule.Arn""",
                terraform_template="""# Monitor for unusual outbound authentication traffic

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty (monitors unusual network behaviour)
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "forced-auth-network-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route unusual network findings to email
resource "aws_cloudwatch_event_rule" "network_findings" {
  name = "guardduty-network-alerts"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "Behavior:EC2/NetworkPortUnusual" },
        { prefix = "Behavior:EC2/TrafficVolumeUnusual" }
      ]
    }
  })
}

resource "aws_sqs_queue" "dlq" {
  name                      = "forced-auth-network-alerts-dlq"
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.network_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.alerts.arn

  retry_policy {
    maximum_retry_attempts       = 8
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.network_findings.arn
        }
      }
    }]
  })
}""",
                alert_severity="high",
                alert_title="GuardDuty: Unusual Network Authentication Activity",
                alert_description_template=(
                    "GuardDuty detected unusual network activity: {finding_type}. "
                    "Instance: {instance_id}. Destination: {remote_ip}:{remote_port}. "
                    "This may indicate forced authentication or credential theft attempts."
                ),
                investigation_steps=[
                    "Identify the source EC2 instance and its purpose",
                    "Review VPC Flow Logs for the affected instance",
                    "Check destination IPs against threat intelligence",
                    "Examine instance for phishing lures (LNK, SCF files, malicious documents)",
                    "Review CloudTrail for recent changes to the instance",
                    "Check for SMB/WebDAV connections to external hosts",
                ],
                containment_actions=[
                    "Isolate the affected instance using security groups",
                    "Block outbound SMB (139/445) and WebDAV traffic at the network level",
                    "Scan the instance for malicious files",
                    "Review and rotate credentials for users who accessed the instance",
                    "Enable VPC Flow Logs if not already active",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal network behaviour; whitelist known file servers and authentication endpoints",
            detection_coverage="50% - catches unusual network patterns",
            evasion_considerations="Attackers may use common ports or slow exfiltration",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events",
            prerequisites=[
                "AWS account with appropriate IAM permissions",
                "GuardDuty supported region",
            ],
        ),
        # Strategy 2: AWS - VPC Flow Logs Analysis for SMB/WebDAV
        DetectionStrategy(
            strategy_id="t1187-aws-flowlogs",
            name="VPC Flow Logs: SMB and WebDAV Connection Monitoring",
            description=(
                "Analyse VPC Flow Logs to detect outbound connections on SMB (139/445) "
                "and WebDAV (80/443) ports to external destinations, which may indicate "
                "forced authentication credential harvesting attempts."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, srcaddr, dstaddr, dstport, bytes, packets
| filter dstport in [139, 445] and action = "ACCEPT"
| filter dstaddr not like /^10\\.|^172\\.(1[6-9]|2[0-9]|3[01])\\.|^192\\.168\\./
| stats count(*) as connection_count,
        sum(bytes) as total_bytes,
        count_distinct(dstaddr) as unique_destinations
  by srcaddr, bin(1h) as time_window
| filter connection_count > 3 or unique_destinations > 2
| sort time_window desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on outbound SMB connections to external hosts

Parameters:
  VPCFlowLogGroup:
    Type: String
  AlertEmail:
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

  # Step 2: Metric filter for outbound SMB
  OutboundSMBFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref VPCFlowLogGroup
      FilterPattern: '[version, account, eni, source, destination, srcport, destport=445||destport=139, protocol, packets, bytes, windowstart, windowend, action=ACCEPT, flowlogstatus]'
      MetricTransformations:
        - MetricName: OutboundSMBConnections
          MetricNamespace: Security/ForcedAuth
          MetricValue: "1"

  # Step 3: Alert on threshold
  OutboundSMBAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1187-OutboundSMB
      MetricName: OutboundSMBConnections
      Namespace: Security/ForcedAuth
      Statistic: Sum
      Period: 300
      Threshold: 3
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Alert on outbound SMB connections to external hosts

variable "vpc_flow_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create alert topic
resource "aws_sns_topic" "alerts" {
  name = "outbound-smb-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for outbound SMB
resource "aws_cloudwatch_log_metric_filter" "outbound_smb" {
  name           = "outbound-smb-connections"
  log_group_name = var.vpc_flow_log_group
  pattern        = "[version, account, eni, source, destination, srcport, destport=445||destport=139, protocol, packets, bytes, windowstart, windowend, action=ACCEPT, flowlogstatus]"

  metric_transformation {
    name      = "OutboundSMBConnections"
    namespace = "Security/ForcedAuth"
    value     = "1"
  }
}

# Step 3: Alert on threshold
resource "aws_cloudwatch_metric_alarm" "outbound_smb" {
  alarm_name          = "T1187-OutboundSMB"
  metric_name         = "OutboundSMBConnections"
  namespace           = "Security/ForcedAuth"
  statistic           = "Sum"
  period              = 300
  threshold           = 3
  comparison_operator = "GreaterThanOrEqualToThreshold"
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
                alert_title="Outbound SMB Connections to External Hosts Detected",
                alert_description_template=(
                    "Instance {srcaddr} made {connection_count} outbound SMB connections "
                    "to {unique_destinations} external destinations in 1 hour. "
                    "This may indicate forced authentication or credential harvesting."
                ),
                investigation_steps=[
                    "Identify all external IPs contacted on SMB ports",
                    "Check if destination IPs are known malicious (threat intelligence)",
                    "Review the source instance for malicious files (LNK, SCF, documents with external links)",
                    "Check CloudTrail for recent S3 downloads or file modifications",
                    "Examine user activity on the affected instance",
                    "Look for scheduled tasks or cron jobs making these connections",
                ],
                containment_actions=[
                    "Block SMB ports (139/445) outbound at VPC level using NACLs",
                    "Isolate the affected instance",
                    "Scan for and remove malicious lure files",
                    "Force password reset for users who accessed the instance",
                    "Review and update security group rules",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known external file servers; exclude instances with legitimate SMB requirements",
            detection_coverage="80% - catches most SMB-based forced authentication",
            evasion_considerations="Use of WebDAV on port 80/443 instead of SMB",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=["VPC Flow Logs enabled", "Flow logs sent to CloudWatch"],
        ),
        # Strategy 3: AWS - IMDS Credential Theft Detection
        DetectionStrategy(
            strategy_id="t1187-aws-imds",
            name="EC2 Instance Metadata Service (IMDS) Abuse Detection",
            description=(
                "Detect unauthorised access to EC2 Instance Metadata Service (IMDS) "
                "which can be exploited to steal IAM role credentials through SSRF "
                "or similar forced authentication vectors."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress,
       eventName, errorCode
| filter eventSource = "sts.amazonaws.com"
  and eventName = "AssumeRole"
  and userIdentity.type = "AWSService"
  and userIdentity.principalId like /^AIDAI/
| stats count(*) as assume_role_count,
        count_distinct(sourceIPAddress) as unique_ips
  by userIdentity.principalId, bin(15m) as time_window
| filter assume_role_count > 10 or unique_ips > 3
| sort time_window desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect unusual IMDS credential retrieval patterns

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
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

  # Step 2: Metric for unusual IMDS access
  IMDSAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "sts.amazonaws.com" && $.eventName = "AssumeRole" && $.userIdentity.type = "AWSService" }'
      MetricTransformations:
        - MetricName: IMDSCredentialRetrieval
          MetricNamespace: Security/ForcedAuth
          MetricValue: "1"

  # Step 3: Alert on unusual volume
  IMDSAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1187-IMDS-Abuse
      MetricName: IMDSCredentialRetrieval
      Namespace: Security/ForcedAuth
      Statistic: Sum
      Period: 900
      Threshold: 20
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect unusual IMDS credential retrieval patterns

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create alert topic
resource "aws_sns_topic" "alerts" {
  name = "imds-abuse-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric for unusual IMDS access
resource "aws_cloudwatch_log_metric_filter" "imds_access" {
  name           = "imds-credential-retrieval"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"sts.amazonaws.com\" && $.eventName = \"AssumeRole\" && $.userIdentity.type = \"AWSService\" }"

  metric_transformation {
    name      = "IMDSCredentialRetrieval"
    namespace = "Security/ForcedAuth"
    value     = "1"
  }
}

# Step 3: Alert on unusual volume
resource "aws_cloudwatch_metric_alarm" "imds_abuse" {
  alarm_name          = "T1187-IMDS-Abuse"
  metric_name         = "IMDSCredentialRetrieval"
  namespace           = "Security/ForcedAuth"
  statistic           = "Sum"
  period              = 900
  threshold           = 20
  comparison_operator = "GreaterThanOrEqualToThreshold"
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
                alert_severity="critical",
                alert_title="Unusual EC2 Instance Metadata Service Access",
                alert_description_template=(
                    "Detected {assume_role_count} IMDS credential retrievals in 15 minutes "
                    "from instance role {principalId}. This may indicate SSRF exploitation "
                    "or forced credential harvesting."
                ),
                investigation_steps=[
                    "Identify the EC2 instance and associated IAM role",
                    "Check application logs for SSRF vulnerabilities",
                    "Review VPC Flow Logs for unusual HTTP requests",
                    "Examine CloudTrail for API calls made with the retrieved credentials",
                    "Check if IMDSv2 (session-based) is enforced",
                    "Look for web application or service exploitation",
                ],
                containment_actions=[
                    "Enforce IMDSv2 (require session tokens) on all EC2 instances",
                    "Rotate IAM role credentials immediately",
                    "Restrict instance metadata access using iptables if needed",
                    "Patch any SSRF vulnerabilities in applications",
                    "Review IAM role permissions and apply least privilege",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal IMDS access patterns for each instance role; exclude auto-scaling groups with high turnover",
            detection_coverage="70% - effective for IMDS-based credential theft",
            evasion_considerations="Slow, rate-limited credential retrieval; use of IMDSv2 bypass techniques",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["CloudTrail enabled with STS events logged"],
        ),
        # Strategy 4: GCP - Unusual Metadata Service Access
        DetectionStrategy(
            strategy_id="t1187-gcp-metadata",
            name="GCP Metadata Server Credential Theft Detection",
            description=(
                "Detect unauthorised or unusual access to GCP Compute Engine metadata "
                "service which can be exploited via SSRF to steal service account tokens."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_instance"
httpRequest.requestUrl=~"metadata.google.internal/computeMetadata/v1/instance/service-accounts"
httpRequest.status>=200
httpRequest.status<300""",
                gcp_terraform_template="""# GCP: Detect metadata service credential theft

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for metadata access
resource "google_logging_metric" "metadata_access" {
  name   = "metadata-service-credential-access"
  filter = <<-EOT
    resource.type="gce_instance"
    httpRequest.requestUrl=~"metadata.google.internal/computeMetadata/v1/instance/service-accounts"
    httpRequest.status>=200
    httpRequest.status<300
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for unusual access
resource "google_monitoring_alert_policy" "metadata_theft" {
  display_name = "Metadata Service Credential Theft"
  combiner     = "OR"

  conditions {
    display_name = "High metadata access rate"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.metadata_access.name}\""
      duration        = "900s"
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
    auto_close = "86400s"
  }
}""",
                alert_severity="critical",
                alert_title="GCP Metadata Service Credential Access Detected",
                alert_description_template=(
                    "Unusual access to GCP metadata service detected from instance {instance_id}. "
                    "Service account token endpoint accessed {access_count} times in 15 minutes. "
                    "This may indicate SSRF exploitation or forced authentication."
                ),
                investigation_steps=[
                    "Identify the GCE instance and its purpose",
                    "Review application logs for SSRF vulnerabilities",
                    "Check Cloud Logging for the source of metadata requests",
                    "Examine what APIs were called with the stolen token",
                    "Verify if metadata concealment is enabled",
                    "Check for compromised web applications or services",
                ],
                containment_actions=[
                    "Enable metadata concealment on the instance",
                    "Rotate the service account key immediately",
                    "Restrict metadata access using firewall rules",
                    "Patch SSRF vulnerabilities in applications",
                    "Apply least privilege to service account permissions",
                    "Consider using Workload Identity instead of instance service accounts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal metadata access for each instance; exclude instances with known high metadata usage",
            detection_coverage="75% - effective for metadata-based credential theft",
            evasion_considerations="Slow, rate-limited access; use of proxies to obscure source",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="£8-12",
            prerequisites=[
                "Cloud Logging enabled",
                "HTTP request logging enabled on GCE instances",
            ],
        ),
        # Strategy 5: GCP - VPC Flow Logs for SMB Traffic
        DetectionStrategy(
            strategy_id="t1187-gcp-flowlogs",
            name="GCP VPC Flow Logs: Outbound SMB Monitoring",
            description=(
                "Monitor GCP VPC Flow Logs for outbound SMB connections from GCE instances "
                "to external destinations, indicating potential forced authentication attempts."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""resource.type="gce_subnetwork"
logName=~"vpc_flows"
jsonPayload.connection.dest_port=(139 OR 445)
jsonPayload.reporter="SRC"
NOT ip_in_net(jsonPayload.connection.dest_ip, "10.0.0.0/8")
NOT ip_in_net(jsonPayload.connection.dest_ip, "172.16.0.0/12")
NOT ip_in_net(jsonPayload.connection.dest_ip, "192.168.0.0/16")""",
                gcp_terraform_template="""# GCP: Monitor outbound SMB traffic

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for outbound SMB
resource "google_logging_metric" "outbound_smb" {
  name   = "outbound-smb-connections"
  filter = <<-EOT
    resource.type="gce_subnetwork"
    logName=~"vpc_flows"
    jsonPayload.connection.dest_port=(139 OR 445)
    jsonPayload.reporter="SRC"
    NOT ip_in_net(jsonPayload.connection.dest_ip, "10.0.0.0/8")
    NOT ip_in_net(jsonPayload.connection.dest_ip, "172.16.0.0/12")
    NOT ip_in_net(jsonPayload.connection.dest_ip, "192.168.0.0/16")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert on outbound SMB connections
resource "google_monitoring_alert_policy" "outbound_smb" {
  display_name = "Outbound SMB Connections Detected"
  combiner     = "OR"

  conditions {
    display_name = "External SMB connections"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.outbound_smb.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="Outbound SMB Connections from GCP Instance",
                alert_description_template=(
                    "GCE instance {instance_id} established outbound SMB connections to "
                    "external IP {dest_ip}. This may indicate forced authentication or "
                    "credential harvesting activity."
                ),
                investigation_steps=[
                    "Identify the source GCE instance",
                    "Check destination IPs against threat intelligence",
                    "Review instance for malicious files (LNK, SCF, documents)",
                    "Examine Cloud Logging for recent file operations",
                    "Check for SSH access or compromised accounts",
                    "Review firewall rules allowing outbound SMB",
                ],
                containment_actions=[
                    "Create firewall rule blocking outbound SMB (tcp:139,445)",
                    "Isolate the affected instance using VPC firewall tags",
                    "Scan for and remove malicious lure files",
                    "Reset passwords for users with instance access",
                    "Review and update VPC firewall rules to deny outbound SMB by default",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known external file servers; exclude instances with documented SMB requirements",
            detection_coverage="80% - highly effective for SMB-based attacks",
            evasion_considerations="Use of WebDAV or other protocols; slow connection attempts",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="£10-18",
            prerequisites=["VPC Flow Logs enabled", "Flow logs sent to Cloud Logging"],
        ),
    ],
    recommended_order=[
        "t1187-aws-network",
        "t1187-aws-flowlogs",
        "t1187-aws-imds",
        "t1187-gcp-metadata",
        "t1187-gcp-flowlogs",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+25% improvement for Credential Access tactic",
)
