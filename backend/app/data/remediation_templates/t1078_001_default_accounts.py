"""
T1078.001 - Valid Accounts: Default Accounts

Adversaries may obtain and abuse credentials of default accounts as a means
of gaining initial access, persistence, privilege escalation, or defence evasion.
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
    technique_id="T1078.001",
    technique_name="Valid Accounts: Default Accounts",
    tactic_ids=["TA0001", "TA0003", "TA0004", "TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1078/001/",

    threat_context=ThreatContext(
        description=(
            "Adversaries exploit pre-configured default accounts built into operating systems, "
            "applications, and cloud platforms. These accounts include Windows Guest/Administrator, "
            "AWS root user, ESXi root user, and Kubernetes default service accounts. Default accounts "
            "pose significant risks when credentials remain unchanged after installation, as they are "
            "well-known and often targeted by attackers."
        ),
        attacker_goal="Gain legitimate access using well-known default credentials without triggering security alerts",
        why_technique=[
            "Default credentials are widely documented and easily found online",
            "Many organisations fail to change default passwords after deployment",
            "Default accounts often have elevated privileges",
            "Legitimate account usage bypasses many security controls",
            "No malware deployment required, reducing detection surface"
        ],
        known_threat_actors=["Ember Bear", "FIN13", "Magic Hound", "UNC3886"],
        recent_campaigns=[
            Campaign(
                name="Ember Bear IP Camera Exploitation",
                year=2022,
                description="Ember Bear exploited default credentials on internet-facing IP cameras to gain initial access",
                reference_url="https://attack.mitre.org/groups/G1003/"
            ),
            Campaign(
                name="FIN13 Default Credential Abuse",
                year=2023,
                description="FIN13 leveraged default credentials for myWebMethods and QLogic interfaces during targeted intrusions",
                reference_url="https://attack.mitre.org/groups/G1016/"
            ),
            Campaign(
                name="Magic Hound Exchange Server Compromise",
                year=2021,
                description="Magic Hound activated DefaultAccount to gain RDP access to Exchange servers",
                reference_url="https://attack.mitre.org/groups/G0059/"
            ),
            Campaign(
                name="UNC3886 vCenter Exploitation",
                year=2023,
                description="UNC3886 harvested default vCenter Server service account credentials for persistent access",
                reference_url="https://attack.mitre.org/groups/G1040/"
            )
        ],
        prevalence="common",
        trend="stable",
        severity_score=8,
        severity_reasoning=(
            "Default account exploitation is a persistent threat affecting cloud infrastructure, "
            "virtualisation platforms, and IoT devices. Success provides immediate privileged access "
            "with minimal detection, as the activity appears as legitimate system operations. "
            "Particularly dangerous in cloud environments where root/admin accounts have unrestricted access."
        ),
        business_impact=[
            "Complete infrastructure compromise via root/admin access",
            "Data exfiltration without triggering user behaviour analytics",
            "Persistence through legitimate system accounts",
            "Lateral movement using privileged credentials",
            "Compliance violations for inadequate access management"
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1098", "T1136", "T1087", "T1069"],
        often_follows=["T1595", "T1592", "T1589"]
    ),

    detection_strategies=[
        # Strategy 1: AWS Root Account Monitoring
        DetectionStrategy(
            strategy_id="t1078001-aws-root",
            name="AWS Root Account Activity Detection",
            description=(
                "Monitor and alert on any usage of the AWS root account, which should only be used "
                "for initial setup and rare administrative tasks. Root account activity is a critical "
                "security indicator."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, eventName, sourceIPAddress, userAgent, errorCode
| filter userIdentity.type = "Root" and userIdentity.invokedBy != "AWS Internal"
| filter eventName != "ConsoleLogin" or responseElements.ConsoleLogin != "Failure"
| stats count(*) as activity_count by eventName, sourceIPAddress, bin(5m)
| sort @timestamp desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on AWS root account usage for T1078.001

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for root account alerts

Resources:
  # Step 1: Create SNS topic for root account alerts
  RootAccountAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Root Account Activity Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for root account usage
  RootAccountFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
      MetricTransformations:
        - MetricName: RootAccountUsage
          MetricNamespace: Security/T1078
          MetricValue: "1"

  # Step 3: Create alarm for root account activity
  RootAccountAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1078-RootAccountUsage
      AlarmDescription: AWS root account was used - potential default account abuse
      MetricName: RootAccountUsage
      Namespace: Security/T1078
      Statistic: Sum
      Period: 60
      EvaluationPeriods: 1
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref RootAccountAlertTopic
      TreatMissingData: notBreaching''',
                terraform_template='''# AWS Root Account Activity Detection

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for root account alerts"
}

# Step 1: Create SNS topic for root account alerts
resource "aws_sns_topic" "root_alerts" {
  name         = "root-account-activity-alerts"
  display_name = "Root Account Activity Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.root_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for root account usage
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "root-account-usage"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "Security/T1078"
    value     = "1"
  }
}

# Step 3: Create alarm for root account activity
resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "T1078-RootAccountUsage"
  alarm_description   = "AWS root account was used - potential default account abuse"
  metric_name         = "RootAccountUsage"
  namespace           = "Security/T1078"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.root_alerts.arn]
  treat_missing_data  = "notBreaching"
}''',
                alert_severity="critical",
                alert_title="AWS Root Account Activity Detected",
                alert_description_template=(
                    "AWS root account was used for {eventName} from IP {source_ip}. "
                    "Root account usage should be extremely rare and investigated immediately."
                ),
                investigation_steps=[
                    "Verify root account MFA is enabled and check MFA device serial number",
                    "Identify all actions taken by root account in the last 24 hours",
                    "Determine if root account usage was scheduled/approved",
                    "Check source IP against known corporate IPs and geolocation",
                    "Review IAM credential report for root account access keys",
                    "Verify no root access keys exist (they should be deleted)"
                ],
                containment_actions=[
                    "Immediately rotate root account password if unauthorised",
                    "Delete any root account access keys if they exist",
                    "Enable MFA on root account if not already enabled",
                    "Review and revoke any changes made during root session",
                    "Enable CloudTrail in all regions if not already enabled"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Suppress alerts during approved maintenance windows; document all legitimate root usage",
            detection_coverage="100% - catches all root account activity in CloudTrail",
            evasion_considerations="Attackers may disable CloudTrail, use access keys instead of console, or operate from expected IPs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled and logging to CloudWatch Logs", "Root account MFA enabled"]
        ),

        # Strategy 2: Default Service Account Activity (AWS)
        DetectionStrategy(
            strategy_id="t1078001-aws-default-service",
            name="AWS Default Service Account Activity Detection",
            description=(
                "Detect activity from AWS service-linked roles and default service accounts "
                "that are performing unusual actions outside their normal scope."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.arn, eventName, sourceIPAddress, userAgent
| filter userIdentity.type = "AssumedRole"
| filter userIdentity.principalId like /AWSServiceRole/
| filter eventName in ["CreateUser", "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy",
    "PutUserPolicy", "PutRolePolicy", "CreateRole", "DeleteLogStream", "DeleteLogGroup"]
| stats count(*) as suspicious_actions by userIdentity.arn, eventName, bin(1h)
| sort @timestamp desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious default service account activity

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for service account alerts
  ServiceAccountAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for service account IAM changes
  ServiceAccountIAMFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.userIdentity.principalId = "*AWSServiceRole*") && ($.eventName = "CreateUser" || $.eventName = "CreateAccessKey" || $.eventName = "AttachUserPolicy" || $.eventName = "AttachRolePolicy") }'
      MetricTransformations:
        - MetricName: ServiceAccountIAMActivity
          MetricNamespace: Security/T1078
          MetricValue: "1"

  # Step 3: Alarm on suspicious service account activity
  ServiceAccountAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1078-SuspiciousServiceAccountActivity
      AlarmDescription: Default service account performed IAM modifications
      MetricName: ServiceAccountIAMActivity
      Namespace: Security/T1078
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref ServiceAccountAlertTopic''',
                terraform_template='''# Detect suspicious default service account activity

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for service account alerts
resource "aws_sns_topic" "service_account_alerts" {
  name = "service-account-activity-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.service_account_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for service account IAM changes
resource "aws_cloudwatch_log_metric_filter" "service_account_iam" {
  name           = "service-account-iam-activity"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.userIdentity.principalId = \"*AWSServiceRole*\") && ($.eventName = \"CreateUser\" || $.eventName = \"CreateAccessKey\" || $.eventName = \"AttachUserPolicy\" || $.eventName = \"AttachRolePolicy\") }"

  metric_transformation {
    name      = "ServiceAccountIAMActivity"
    namespace = "Security/T1078"
    value     = "1"
  }
}

# Step 3: Alarm on suspicious service account activity
resource "aws_cloudwatch_metric_alarm" "service_account" {
  alarm_name          = "T1078-SuspiciousServiceAccountActivity"
  alarm_description   = "Default service account performed IAM modifications"
  metric_name         = "ServiceAccountIAMActivity"
  namespace           = "Security/T1078"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.service_account_alerts.arn]
}''',
                alert_severity="high",
                alert_title="Suspicious Default Service Account Activity",
                alert_description_template=(
                    "Service account {principal} executed {eventName}, which is unusual for this role type. "
                    "Possible default account abuse or privilege escalation."
                ),
                investigation_steps=[
                    "Identify the specific service account and its intended purpose",
                    "Review all recent activity from this service account",
                    "Verify if the actions align with the service's normal operations",
                    "Check for any recent permission changes to the service role",
                    "Investigate any resources created or modified by the service account"
                ],
                containment_actions=[
                    "Review and restrict service role permissions to minimum required",
                    "Revoke any suspicious permissions or policies added",
                    "Check for and remove any backdoor accounts created",
                    "Review service role trust relationships for compromise"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal service account behaviour; whitelist known automation workflows",
            detection_coverage="70% - catches unusual IAM actions from service roles",
            evasion_considerations="Attackers may use service accounts within their normal operational scope",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "Understanding of service account baselines"]
        ),

        # Strategy 3: GCP Default Service Account Monitoring
        DetectionStrategy(
            strategy_id="t1078001-gcp-default-service",
            name="GCP Default Service Account Activity Detection",
            description=(
                "Monitor GCP default Compute Engine and App Engine service accounts for "
                "suspicious activity. These accounts have elevated permissions by default and "
                "should not be used for production workloads."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.authenticationInfo.principalEmail=~".*-compute@developer.gserviceaccount.com"
OR protoPayload.authenticationInfo.principalEmail=~".*@appspot.gserviceaccount.com"
AND (
    protoPayload.methodName=~".*iam.*.create.*"
    OR protoPayload.methodName=~".*iam.*.delete.*"
    OR protoPayload.methodName=~".*iam.*.setIamPolicy.*"
    OR protoPayload.methodName=~".*storage.*.delete.*"
    OR protoPayload.methodName="v1.compute.instances.delete"
)
severity >= "WARNING"''',
                gcp_terraform_template='''# GCP: Detect default service account abuse

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for alerts"
}

# Step 1: Create log sink for default service account activity
resource "google_logging_project_sink" "default_service_account" {
  name        = "default-service-account-activity"
  destination = "pubsub.googleapis.com/projects/${var.project_id}/topics/default-sa-alerts"

  filter = <<-EOT
    protoPayload.authenticationInfo.principalEmail=~".*-compute@developer.gserviceaccount.com"
    OR protoPayload.authenticationInfo.principalEmail=~".*@appspot.gserviceaccount.com"
    AND (
        protoPayload.methodName=~".*iam.*.create.*"
        OR protoPayload.methodName=~".*iam.*.delete.*"
        OR protoPayload.methodName=~".*iam.*.setIamPolicy.*"
        OR protoPayload.methodName=~".*storage.*.delete.*"
        OR protoPayload.methodName="v1.compute.instances.delete"
    )
    severity >= "WARNING"
  EOT

  unique_writer_identity = true
}

# Step 2: Create Pub/Sub topic for alerts
resource "google_pubsub_topic" "default_sa_alerts" {
  name = "default-sa-alerts"
}

# Step 3: Create alert notification channel and policy
resource "google_monitoring_notification_channel" "email" {
  display_name = "Default SA Alert Email"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

resource "google_monitoring_alert_policy" "default_sa_activity" {
  display_name = "T1078.001 - Default Service Account Activity"
  combiner     = "OR"

  conditions {
    display_name = "Default service account suspicious activity"

    condition_matched_log {
      filter = google_logging_project_sink.default_service_account.filter
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
  }
}''',
                alert_severity="high",
                alert_title="GCP Default Service Account Suspicious Activity",
                alert_description_template=(
                    "Default service account {principal_email} executed {method_name}. "
                    "Default service accounts should not be used for production operations."
                ),
                investigation_steps=[
                    "Identify which GCE instance or App Engine application is using the default service account",
                    "Review all recent API calls made by this service account",
                    "Check if default service account has been granted additional IAM roles",
                    "Investigate the workload running on the instance/application",
                    "Verify if this is a legitimate application or a compromised resource"
                ],
                containment_actions=[
                    "Stop the instance or disable the application if unauthorised",
                    "Create a custom service account with minimal permissions",
                    "Migrate workload to use custom service account",
                    "Disable default service account if possible",
                    "Review and revoke any excessive IAM bindings on default accounts"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning=(
                "Create exceptions for known legacy applications still using default service accounts; "
                "focus on IAM and destructive operations rather than routine API calls"
            ),
            detection_coverage="80% - catches high-risk operations from default service accounts",
            evasion_considerations="Attackers may use default accounts for reconnaissance rather than destructive actions",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Logging enabled", "Audit logs enabled for IAM and Compute Engine"]
        ),

        # Strategy 4: SSH Root Login Detection
        DetectionStrategy(
            strategy_id="t1078001-ssh-root",
            name="SSH Root Account Login Detection",
            description=(
                "Detect direct SSH logins using the root account on Linux instances. "
                "Root SSH access should be disabled in favour of using sudo."
            ),
            detection_type=DetectionType.CUSTOM_LAMBDA,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, @message
| filter @message like /Accepted.*for root/
| parse @message /Accepted (?<auth_method>\\w+) for (?<user>\\w+) from (?<source_ip>[\\d.]+)/
| stats count(*) as login_count by source_ip, bin(5m)
| sort @timestamp desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect SSH root logins on EC2 instances

Parameters:
  SystemLogGroup:
    Type: String
    Description: Log group containing /var/log/auth.log or /var/log/secure
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for root SSH alerts
  RootSSHAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for root SSH logins
  RootSSHFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref SystemLogGroup
      FilterPattern: '[Mon, day, timestamp, ip, id, msg1="Accepted", auth_method, msg2="for", user="root", ...]'
      MetricTransformations:
        - MetricName: RootSSHLogin
          MetricNamespace: Security/T1078
          MetricValue: "1"

  # Step 3: Alarm on root SSH login
  RootSSHAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1078-RootSSHLogin
      AlarmDescription: SSH login detected using root account
      MetricName: RootSSHLogin
      Namespace: Security/T1078
      Statistic: Sum
      Period: 60
      EvaluationPeriods: 1
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref RootSSHAlertTopic''',
                terraform_template='''# Detect SSH root logins on EC2 instances

variable "system_log_group" {
  type        = string
  description = "Log group containing /var/log/auth.log or /var/log/secure"
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for root SSH alerts
resource "aws_sns_topic" "root_ssh_alerts" {
  name = "root-ssh-login-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.root_ssh_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for root SSH logins
resource "aws_cloudwatch_log_metric_filter" "root_ssh" {
  name           = "root-ssh-login"
  log_group_name = var.system_log_group
  pattern        = "[Mon, day, timestamp, ip, id, msg1=\"Accepted\", auth_method, msg2=\"for\", user=\"root\", ...]"

  metric_transformation {
    name      = "RootSSHLogin"
    namespace = "Security/T1078"
    value     = "1"
  }
}

# Step 3: Alarm on root SSH login
resource "aws_cloudwatch_metric_alarm" "root_ssh" {
  alarm_name          = "T1078-RootSSHLogin"
  alarm_description   = "SSH login detected using root account"
  metric_name         = "RootSSHLogin"
  namespace           = "Security/T1078"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.root_ssh_alerts.arn]
}''',
                alert_severity="high",
                alert_title="Root SSH Login Detected",
                alert_description_template=(
                    "SSH login detected for root account from IP {source_ip} using {auth_method}. "
                    "Direct root SSH access violates security best practices."
                ),
                investigation_steps=[
                    "Identify the EC2 instance where root login occurred",
                    "Check if the source IP is authorised and expected",
                    "Review all commands executed during the root session",
                    "Verify SSH key used matches authorised keys",
                    "Check /root/.ssh/authorized_keys for unauthorised entries",
                    "Review security group rules for SSH access restrictions"
                ],
                containment_actions=[
                    "Disable root SSH login by setting 'PermitRootLogin no' in sshd_config",
                    "Remove all entries from /root/.ssh/authorized_keys",
                    "Terminate active SSH sessions for root user",
                    "Rotate all SSH keys on the instance",
                    "Review and restrict security group rules for SSH access",
                    "Enable AWS Systems Manager Session Manager as SSH alternative"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist approved maintenance IPs; suppress during planned maintenance windows",
            detection_coverage="100% - catches all successful root SSH logins if logs are shipped to CloudWatch",
            evasion_considerations="Attackers may disable logging, clear auth logs, or use console/serial access",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-15 depending on instance count",
            prerequisites=[
                "CloudWatch Logs agent installed on instances",
                "System authentication logs (/var/log/auth.log or /var/log/secure) shipped to CloudWatch"
            ]
        ),

        # Strategy 5: Config Rule - Root Account MFA
        DetectionStrategy(
            strategy_id="t1078001-root-mfa",
            name="AWS Config - Root Account MFA Enforcement",
            description=(
                "Use AWS Config to continuously verify that root account has MFA enabled. "
                "This preventive control makes default root account exploitation significantly harder."
            ),
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="config",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                config_rule_identifier="ROOT_ACCOUNT_MFA_ENABLED",
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: AWS Config rule to verify root account MFA

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable AWS Config (if not already enabled)
  ConfigRecorder:
    Type: AWS::Config::ConfigurationRecorder
    Properties:
      RoleArn: !GetAtt ConfigRole.Arn
      RecordingGroup:
        AllSupported: true
        IncludeGlobalResourceTypes: true

  ConfigRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: config.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/ConfigRole

  # Step 2: Root account MFA compliance rule
  RootAccountMFARule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: root-account-mfa-enabled
      Description: Verify root account has MFA enabled
      Source:
        Owner: AWS
        SourceIdentifier: ROOT_ACCOUNT_MFA_ENABLED

  # Step 3: Alert on non-compliance
  ComplianceAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail''',
                terraform_template='''# AWS Config rule to verify root account MFA

variable "alert_email" {
  type = string
}

# Step 1: Enable AWS Config (if not already enabled)
resource "aws_config_configuration_recorder" "main" {
  name     = "main-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_iam_role" "config" {
  name = "config-recorder-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "config.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

# Step 2: Root account MFA compliance rule
resource "aws_config_config_rule" "root_mfa" {
  name        = "root-account-mfa-enabled"
  description = "Verify root account has MFA enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Step 3: Alert on non-compliance
resource "aws_sns_topic" "compliance_alerts" {
  name = "config-compliance-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.compliance_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}''',
                alert_severity="critical",
                alert_title="Root Account MFA Not Enabled",
                alert_description_template=(
                    "AWS Config detected that root account MFA is not enabled. "
                    "This significantly increases the risk of account compromise."
                ),
                investigation_steps=[
                    "Verify current MFA status in IAM security credentials",
                    "Check if MFA was recently disabled or removed",
                    "Review CloudTrail for any DeactivateMFADevice events",
                    "Verify no unauthorised access to root account has occurred"
                ],
                containment_actions=[
                    "Immediately enable MFA on root account using virtual or hardware MFA",
                    "Store MFA device backup codes in secure offline location",
                    "Document MFA device serial number and type",
                    "Verify root account password was not changed",
                    "Review all root account activity in CloudTrail"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="None needed - this should always be compliant",
            detection_coverage="100% - continuously monitors root account MFA status",
            evasion_considerations="Attackers may disable Config or modify rules; use SCPs to prevent Config changes",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-3 for Config rule evaluation",
            prerequisites=["AWS Config enabled in account"]
        )
    ],

    recommended_order=[
        "t1078001-aws-root",
        "t1078001-root-mfa",
        "t1078001-aws-default-service",
        "t1078001-gcp-default-service",
        "t1078001-ssh-root"
    ],
    total_effort_hours=7.0,
    coverage_improvement="+30% improvement for Initial Access and Privilege Escalation tactics"
)
