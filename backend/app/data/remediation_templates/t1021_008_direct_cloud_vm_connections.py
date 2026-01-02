"""
T1021.008 - Remote Services: Direct Cloud VM Connections

Adversaries exploit valid cloud accounts to gain direct access to cloud-hosted
virtual machines through cloud-native methods. Includes AWS EC2 Instance Connect,
AWS Systems Manager, and Azure Serial Console.
Used by Scattered Spider.
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
    technique_id="T1021.008",
    technique_name="Remote Services: Direct Cloud VM Connections",
    tactic_ids=["TA0008"],
    mitre_url="https://attack.mitre.org/techniques/T1021/008/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit valid cloud accounts to gain direct access to cloud-hosted "
            "virtual machines through cloud-native methods rather than traditional SSH/RDP. "
            "These methods include AWS EC2 Instance Connect, AWS Systems Manager, and Azure "
            "Serial Console. These tools typically grant SYSTEM or root-level access by default, "
            "facilitating lateral movement and privilege escalation within cloud environments."
        ),
        attacker_goal="Gain direct console access to cloud VMs for lateral movement and privilege escalation",
        why_technique=[
            "Provides SYSTEM/root-level access by default",
            "Bypasses traditional network security controls",
            "Uses legitimate cloud-native tools (appears as normal admin activity)",
            "Enables lateral movement across cloud infrastructure",
            "Can evade endpoint detection solutions",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="uncommon",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Provides direct SYSTEM/root-level access to cloud VMs using legitimate tools. "
            "Difficult to distinguish from normal administrative activity. Enables lateral "
            "movement and privilege escalation across cloud infrastructure."
        ),
        business_impact=[
            "Unauthorised VM access and control",
            "Lateral movement across cloud infrastructure",
            "Privilege escalation to SYSTEM/root",
            "Data exfiltration from compute instances",
            "Potential for persistent backdoor installation",
        ],
        typical_attack_phase="lateral_movement",
        often_precedes=["T1078.004", "T1548", "T1005", "T1087"],
        often_follows=["T1078.004", "T1110"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1021_008-aws-ec2-connect",
            name="AWS EC2 Instance Connect Usage",
            description="Detect EC2 Instance Connect sessions, especially from unusual users or locations.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudtrail",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.instanceId, sourceIPAddress, userAgent
| filter eventName = "SendSSHPublicKey"
| stats count(*) as connections by userIdentity.principalId, requestParameters.instanceId, sourceIPAddress, bin(1h)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect EC2 Instance Connect usage

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for EC2 Instance Connect
  EC2ConnectFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "SendSSHPublicKey" }'
      MetricTransformations:
        - MetricName: EC2InstanceConnectUsage
          MetricNamespace: Security/DirectVMAccess
          MetricValue: "1"

  # Step 3: Create alarm for unusual EC2 Instance Connect activity
  EC2ConnectAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EC2InstanceConnectDetection
      AlarmDescription: Detects EC2 Instance Connect usage
      MetricName: EC2InstanceConnectUsage
      Namespace: Security/DirectVMAccess
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions: [!Ref AlertTopic]

  AlertTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
      Topics:
        - !Ref AlertTopic""",
                terraform_template="""# Detect EC2 Instance Connect usage

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "ec2_connect_alerts" {
  name = "ec2-instance-connect-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ec2_connect_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for EC2 Instance Connect
resource "aws_cloudwatch_log_metric_filter" "ec2_connect" {
  name           = "ec2-instance-connect-usage"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"SendSSHPublicKey\" }"

  metric_transformation {
    name      = "EC2InstanceConnectUsage"
    namespace = "Security/DirectVMAccess"
    value     = "1"
  }
}

# Step 3: Create alarm for EC2 Instance Connect activity
resource "aws_cloudwatch_metric_alarm" "ec2_connect_detection" {
  alarm_name          = "EC2InstanceConnectDetection"
  alarm_description   = "Detects EC2 Instance Connect usage"
  metric_name         = "EC2InstanceConnectUsage"
  namespace           = "Security/DirectVMAccess"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ec2_connect_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.ec2_connect_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ec2_connect_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="EC2 Instance Connect Session Detected",
                alert_description_template="EC2 Instance Connect used by {principalId} to access instance {instanceId} from {sourceIPAddress}.",
                investigation_steps=[
                    "Verify the user identity and whether access was authorised",
                    "Check if the source IP is from expected location",
                    "Review the timing (after-hours or unusual time)",
                    "Check what commands were executed on the instance (review OS logs)",
                    "Verify if MFA was used for the cloud account",
                    "Check for subsequent suspicious activity on the instance",
                ],
                containment_actions=[
                    "Disable the compromised user account",
                    "Revoke active sessions on the affected instance",
                    "Rotate instance credentials and SSH keys",
                    "Review and restrict IAM permissions for ec2-instance-connect:SendSSHPublicKey",
                    "Enable EC2 Instance Connect Endpoint for network isolation",
                    "Review instance security groups and network access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Filter known administrative users and expected source IPs",
            detection_coverage="90% - captures all EC2 Instance Connect usage",
            evasion_considerations="Difficult to evade if CloudTrail is enabled; attackers may use compromised legitimate accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1021_008-aws-ssm-sessions",
            name="AWS Systems Manager Session Activity",
            description="Detect Systems Manager Session Manager connections to EC2 instances.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudtrail",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, requestParameters.target, sourceIPAddress, responseElements.sessionId
| filter eventName = "StartSession"
| stats count(*) as sessions by userIdentity.principalId, requestParameters.target, bin(1h)
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect AWS Systems Manager Session Manager usage

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for SSM sessions
  SSMSessionFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "StartSession" }'
      MetricTransformations:
        - MetricName: SSMSessionStarts
          MetricNamespace: Security/DirectVMAccess
          MetricValue: "1"

  # Step 3: Create alarm for SSM session activity
  SSMSessionAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SSMSessionDetection
      AlarmDescription: Detects Systems Manager session starts
      MetricName: SSMSessionStarts
      Namespace: Security/DirectVMAccess
      Statistic: Sum
      Period: 300
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching
      AlarmActions: [!Ref AlertTopic]

  AlertTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCloudWatchAlarms
            Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
      Topics:
        - !Ref AlertTopic""",
                terraform_template="""# Detect AWS Systems Manager Session Manager usage

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "ssm_session_alerts" {
  name = "ssm-session-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssm_session_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for SSM sessions
resource "aws_cloudwatch_log_metric_filter" "ssm_sessions" {
  name           = "ssm-session-starts"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"StartSession\" }"

  metric_transformation {
    name      = "SSMSessionStarts"
    namespace = "Security/DirectVMAccess"
    value     = "1"
  }
}

# Step 3: Create alarm for SSM session activity
resource "aws_cloudwatch_metric_alarm" "ssm_session_detection" {
  alarm_name          = "SSMSessionDetection"
  alarm_description   = "Detects Systems Manager session starts"
  metric_name         = "SSMSessionStarts"
  namespace           = "Security/DirectVMAccess"
  statistic           = "Sum"
  period              = 300
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.ssm_session_alerts.arn]
}

data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.ssm_session_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarms"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.ssm_session_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Systems Manager Session Started",
                alert_description_template="SSM session started by {principalId} to target {target} (Session: {sessionId}).",
                investigation_steps=[
                    "Verify the user identity and authorisation",
                    "Check the target instance and its role",
                    "Review session logs in SSM Session Manager",
                    "Check commands executed during the session (review SSM session logs)",
                    "Verify if MFA was required and used",
                    "Check for data access or modification during session",
                    "Review timing and duration of session",
                ],
                containment_actions=[
                    "Terminate active SSM sessions if suspicious",
                    "Disable compromised user account",
                    "Review and restrict IAM permissions for ssm:StartSession",
                    "Enable session logging to S3 for forensic analysis",
                    "Implement session document restrictions",
                    "Review instance IAM roles and permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="SSM is commonly used for legitimate administration; filter known admin users and maintenance windows",
            detection_coverage="90% - captures all SSM session starts",
            evasion_considerations="Cannot evade if CloudTrail is enabled; attackers may use compromised admin accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with CloudWatch Logs integration"],
        ),
        DetectionStrategy(
            strategy_id="t1021_008-gcp-serial-console",
            name="GCP Serial Console Access Detection",
            description="Detect serial console access to GCP Compute Engine instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.getSerialPortOutput"
OR protoPayload.methodName="beta.compute.instances.getSerialPortOutput"
OR protoPayload.methodName="v1.compute.projects.setCommonInstanceMetadata"''',
                gcp_terraform_template="""# GCP: Detect serial console access to Compute Engine instances

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Serial Console Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for serial console access
resource "google_logging_metric" "serial_console_access" {
  project = var.project_id
  name   = "serial-console-access"
  filter = <<-EOT
    resource.type="gce_instance"
    (protoPayload.methodName="v1.compute.instances.getSerialPortOutput"
    OR protoPayload.methodName="beta.compute.instances.getSerialPortOutput"
    OR protoPayload.methodName="v1.compute.projects.setCommonInstanceMetadata")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User accessing serial console"
    }
  }
  label_extractors = {
    "user" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy for serial console access
resource "google_monitoring_alert_policy" "serial_console_alert" {
  project      = var.project_id
  display_name = "Serial Console Access Detected"
  combiner     = "OR"
  conditions {
    display_name = "Serial console access detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.serial_console_access.name}\" AND resource.type=\"gce_instance\""
      duration        = "0s"
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
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="GCP Serial Console Access Detected",
                alert_description_template="Serial console access to GCP instance by {principalEmail}.",
                investigation_steps=[
                    "Verify the user identity and authorisation for serial console access",
                    "Check which instance was accessed",
                    "Review the timing of access (after-hours activity)",
                    "Check if serial port access is enabled on the instance",
                    "Review instance metadata changes",
                    "Check for suspicious commands or configuration changes",
                    "Verify if the user has legitimate need for serial console access",
                ],
                containment_actions=[
                    "Disable serial port access on sensitive instances",
                    "Revoke IAM permissions for compute.instances.getSerialPortOutput",
                    "Disable compromised user account",
                    "Review and restrict IAM roles granting serial console access",
                    "Enable organisation policy to disable serial port access",
                    "Review instance logs for compromise indicators",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Serial console access is rarely needed; investigate all instances",
            detection_coverage="95% - captures all serial console access attempts",
            evasion_considerations="Cannot evade if Cloud Logging is enabled; attackers may use compromised admin accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Logging enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1021_008-gcp-iap-tunnel",
            name="GCP IAP TCP Forwarding Detection",
            description="Detect Identity-Aware Proxy TCP forwarding to Compute Engine instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
protoPayload.methodName="AuthorizeUser"
protoPayload.serviceName="iap.googleapis.com"''',
                gcp_terraform_template="""# GCP: Detect IAP TCP forwarding to Compute instances

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "IAP Tunnel Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for IAP tunnelling
resource "google_logging_metric" "iap_tunnel_access" {
  project = var.project_id
  name   = "iap-tcp-forwarding"
  filter = <<-EOT
    resource.type="gce_instance"
    protoPayload.methodName="AuthorizeUser"
    protoPayload.serviceName="iap.googleapis.com"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User using IAP tunnel"
    }
    labels {
      key         = "instance"
      value_type  = "STRING"
      description = "Target instance"
    }
  }
  label_extractors = {
    "user"     = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "instance" = "EXTRACT(protoPayload.resourceName)"
  }
}

# Step 3: Create alert policy for IAP tunnelling
resource "google_monitoring_alert_policy" "iap_tunnel_alert" {
  project      = var.project_id
  display_name = "IAP TCP Forwarding Detected"
  combiner     = "OR"
  conditions {
    display_name = "IAP tunnel established"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.iap_tunnel_access.name}\" AND resource.type=\"gce_instance\""
      duration        = "0s"
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
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="low",
                alert_title="GCP IAP TCP Forwarding Detected",
                alert_description_template="IAP tunnel established by {principalEmail} to instance {instance}.",
                investigation_steps=[
                    "Verify the user identity and authorisation",
                    "Check the target instance and its purpose",
                    "Review the timing and duration of tunnel usage",
                    "Check what services were accessed through the tunnel",
                    "Verify if MFA was used for IAP access",
                    "Review instance logs for suspicious activity during tunnel session",
                ],
                containment_actions=[
                    "Revoke IAM permissions for iap.tunnelInstances.accessViaIAP",
                    "Disable compromised user account",
                    "Review and restrict IAP-secured resources",
                    "Enable context-aware access policies for IAP",
                    "Review instance firewall rules allowing IAP",
                    "Implement IP allowlisting for IAP access if appropriate",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="IAP is commonly used for secure access; filter known admin users and expected access patterns",
            detection_coverage="90% - captures IAP tunnel authorisations",
            evasion_considerations="Cannot evade if Cloud Logging is enabled; appears as legitimate IAP usage",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Logging enabled", "IAP enabled for TCP forwarding"],
        ),
    ],
    recommended_order=[
        "t1021_008-aws-ssm-sessions",
        "t1021_008-aws-ec2-connect",
        "t1021_008-gcp-serial-console",
        "t1021_008-gcp-iap-tunnel",
    ],
    total_effort_hours=2.0,
    coverage_improvement="+15% improvement for Lateral Movement tactic",
)
