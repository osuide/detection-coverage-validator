"""
T1204 - User Execution

Adversaries manipulate users into performing actions that enable code execution,
including clicking malicious links, opening files, executing images, or pasting
malicious code. Used by LAPSUS$, Scattered Spider, Lumma Stealer, Raspberry Robin.
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
    technique_id="T1204",
    technique_name="User Execution",
    tactic_ids=["TA0002"],
    mitre_url="https://attack.mitre.org/techniques/T1204/",

    threat_context=ThreatContext(
        description=(
            "Adversaries manipulate users into performing actions that enable malicious code execution. "
            "This includes clicking malicious links, opening malicious files or attachments, executing "
            "container/VM images, copying and pasting malicious code, or loading malicious libraries. "
            "User Execution often follows phishing but can occur during any intrusion phase. Modern "
            "techniques include social engineering via fake CAPTCHA pages, tech support scams, and "
            "impersonation of IT staff to convince users to install remote access tools."
        ),
        attacker_goal="Execute malicious code by exploiting user trust and manipulating human behaviour",
        why_technique=[
            "Bypasses technical security controls through social engineering",
            "Users willingly perform the malicious action",
            "Establishes initial foothold or escalates privileges",
            "Enables remote access tool installation",
            "Difficult to detect as behaviour appears legitimate",
            "Can leverage trusted relationships and impersonation"
        ],
        known_threat_actors=[
            "LAPSUS$ (G1004)",
            "Scattered Spider (G1015)",
            "Lumma Stealer",
            "Raspberry Robin",
            "Pikabot"
        ],
        recent_campaigns=[
            Campaign(
                name="LAPSUS$ Employee Recruitment",
                year=2022,
                description=(
                    "LAPSUS$ recruited target organisation employees or contractors who provided "
                    "credentials and approved MFA prompts, or installed remote management software "
                    "onto corporate workstations enabling initial access."
                ),
                reference_url="https://attack.mitre.org/groups/G1004/"
            ),
            Campaign(
                name="Scattered Spider IT Impersonation",
                year=2023,
                description=(
                    "Scattered Spider impersonated IT and helpdesk staff to instruct victims to "
                    "execute commercial remote access tools, gaining initial access to corporate "
                    "environments through social engineering."
                ),
                reference_url="https://attack.mitre.org/groups/G1015/"
            ),
            Campaign(
                name="Lumma Stealer Fake CAPTCHA",
                year=2024,
                description=(
                    "Lumma Stealer distributed via fake CAPTCHA pages presenting instructions to "
                    "open Windows Run window and paste clipboard contents to execute Base64-encoded "
                    "PowerShell, stealing credentials and session tokens."
                ),
                reference_url="https://attack.mitre.org/software/S1213/"
            ),
            Campaign(
                name="Pikabot Malicious Attachments",
                year=2024,
                description=(
                    "Campaign C0037 required users to interact with malicious email attachments "
                    "to start installation of Pikabot malware, leading to ransomware deployment."
                ),
                reference_url="https://attack.mitre.org/campaigns/C0037/"
            )
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "User Execution remains highly prevalent as adversaries continuously adapt social "
            "engineering techniques. Modern variations like fake CAPTCHA pages and IT impersonation "
            "are increasingly sophisticated. Can lead to complete environment compromise including "
            "cloud infrastructure, ransomware deployment, and data theft. Particularly dangerous "
            "in cloud environments where users may execute malicious images or scripts."
        ),
        business_impact=[
            "Initial access and code execution",
            "Remote access tool installation",
            "Credential and session token theft",
            "Malware and ransomware deployment",
            "Cryptomining resource abuse",
            "Data exfiltration and breach",
            "Insider threat via recruited employees"
        ],
        typical_attack_phase="execution",
        often_precedes=["T1078.004", "T1219", "T1496.001", "T1530", "T1555.006"],
        often_follows=["T1566", "T1189", "T1199"]
    ),

    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1204-aws-instance-user-data",
            name="AWS EC2 User Data Execution Detection",
            description=(
                "Detect suspicious EC2 instance launches with user data scripts that could "
                "execute malicious code, particularly instances launched from user activity "
                "after clicking malicious links in cloud consoles."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, eventName, requestParameters.instanceType, requestParameters.imageId, userIdentity.arn, requestParameters.userData
| filter eventSource = "ec2.amazonaws.com"
| filter eventName = "RunInstances"
| filter ispresent(requestParameters.userData)
| sort @timestamp desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious EC2 instances with user data execution

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for user data execution alerts
  UserDataAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: EC2 User Data Execution Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create metric filter for instance launches with user data
  UserDataMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "RunInstances") && ($.requestParameters.userData = "*") }'
      MetricTransformations:
        - MetricName: InstancesWithUserData
          MetricNamespace: Security/T1204
          MetricValue: "1"

  # Step 3: Create alarm for user data execution
  UserDataAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1204-EC2-UserDataExecution
      AlarmDescription: Detects EC2 instances launched with user data scripts
      MetricName: InstancesWithUserData
      Namespace: Security/T1204
      Statistic: Sum
      Period: 300
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions:
        - !Ref UserDataAlertTopic''',
                terraform_template='''# AWS: Detect suspicious EC2 user data execution

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create SNS topic for user data execution alerts
resource "aws_sns_topic" "user_data_alerts" {
  name         = "ec2-user-data-execution-alerts"
  display_name = "EC2 User Data Execution Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.user_data_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for instance launches with user data
resource "aws_cloudwatch_log_metric_filter" "user_data" {
  name           = "ec2-instances-with-user-data"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ ($.eventName = \"RunInstances\") && ($.requestParameters.userData = \"*\") }"

  metric_transformation {
    name      = "InstancesWithUserData"
    namespace = "Security/T1204"
    value     = "1"
  }
}

# Step 3: Create alarm for user data execution
resource "aws_cloudwatch_metric_alarm" "user_data_execution" {
  alarm_name          = "T1204-EC2-UserDataExecution"
  alarm_description   = "Detects EC2 instances launched with user data scripts"
  metric_name         = "InstancesWithUserData"
  namespace           = "Security/T1204"
  statistic           = "Sum"
  period              = 300
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.user_data_alerts.arn]
}''',
                alert_severity="high",
                alert_title="AWS EC2: Instance Launched with User Data Script",
                alert_description_template=(
                    "EC2 instance launched with user data script by {userIdentity.arn}. "
                    "Instance type: {instanceType}, Image: {imageId}. User may have been "
                    "tricked into executing malicious instance via cloud console."
                ),
                investigation_steps=[
                    "Decode and analyse the user data script contents",
                    "Verify the user who launched the instance and their recent activity",
                    "Check if the AMI is from an approved or external source",
                    "Review CloudTrail for preceding suspicious activity",
                    "Check if user clicked suspicious links before instance launch",
                    "Examine instance network connections and running processes"
                ],
                containment_actions=[
                    "Terminate suspicious instances immediately",
                    "Isolate instance in security group if investigation needed",
                    "Reset credentials for the launching user",
                    "Block unapproved AMIs via Service Control Policies",
                    "Review and restrict EC2 launch permissions",
                    "Implement session recording for cloud console access"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "User data scripts are commonly used for legitimate automation; baseline "
                "normal user data patterns and alert on deviations or unexpected users"
            ),
            detection_coverage="60% - covers EC2 instances with user data scripts",
            evasion_considerations=(
                "Attackers may use heavily obfuscated user data or launch instances "
                "without user data and execute code via SSM or other means"
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled with data events for EC2"]
        ),

        DetectionStrategy(
            strategy_id="t1204-aws-lambda-external-trigger",
            name="AWS Lambda Execution from External Triggers",
            description=(
                "Detect Lambda function executions triggered by suspicious external events, "
                "API calls, or URLs that users may have clicked, potentially executing "
                "malicious serverless code."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, @message, requestId, userIdentity.arn
| filter @type = "START"
| filter userAgent like /Mozilla|curl|wget/
| stats count(*) as executions by userIdentity.arn, bin(5m)
| filter executions > 10
| sort executions desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect suspicious Lambda function executions

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic for Lambda execution alerts
  LambdaAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Suspicious Lambda Execution Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Create EventBridge rule for Lambda invocations
  SuspiciousLambdaRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1204-SuspiciousLambdaExecution
      Description: Detect potentially malicious Lambda function executions
      EventPattern:
        source:
          - aws.lambda
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - Invoke
            - InvokeAsync
      State: ENABLED
      Targets:
        - Id: LambdaAlerts
          Arn: !Ref LambdaAlertTopic

  # Step 3: Allow EventBridge to publish to SNS
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref LambdaAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref LambdaAlertTopic''',
                terraform_template='''# AWS: Detect suspicious Lambda function executions

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

# Step 1: Create SNS topic for Lambda execution alerts
resource "aws_sns_topic" "lambda_alerts" {
  name         = "suspicious-lambda-execution-alerts"
  display_name = "Suspicious Lambda Execution Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.lambda_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for Lambda invocations
resource "aws_cloudwatch_event_rule" "suspicious_lambda" {
  name        = "t1204-suspicious-lambda-execution"
  description = "Detect potentially malicious Lambda function executions"

  event_pattern = jsonencode({
    source      = ["aws.lambda"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["Invoke", "InvokeAsync"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.suspicious_lambda.name
  target_id = "LambdaAlerts"
  arn       = aws_sns_topic.lambda_alerts.arn
}

# Step 3: Allow EventBridge to publish to SNS
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.lambda_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.lambda_alerts.arn
    }]
  })
}''',
                alert_severity="medium",
                alert_title="AWS Lambda: Suspicious Function Execution",
                alert_description_template=(
                    "Lambda function executed by {userIdentity.arn}. "
                    "Function: {functionName}. User may have been tricked into triggering "
                    "malicious serverless code execution."
                ),
                investigation_steps=[
                    "Review Lambda function code for malicious behaviour",
                    "Check function execution logs for suspicious activity",
                    "Identify the trigger source (API Gateway, S3, manual invoke)",
                    "Verify the user or role that invoked the function",
                    "Check for environment variables containing credentials",
                    "Review function IAM permissions and network access"
                ],
                containment_actions=[
                    "Delete or disable suspicious Lambda functions",
                    "Remove Lambda function triggers and API endpoints",
                    "Rotate IAM credentials used by the function",
                    "Review and restrict Lambda execution permissions",
                    "Enable Lambda function concurrency limits",
                    "Implement Lambda code signing for deployment"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning=(
                "Lambda invocations are common in serverless architectures; focus on "
                "unexpected functions, unusual users, or suspicious code patterns"
            ),
            detection_coverage="40% - covers direct Lambda invocations",
            evasion_considerations=(
                "Attackers may use legitimate triggers like API Gateway or S3 events "
                "to obscure the user execution aspect"
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled for Lambda data events"]
        ),

        DetectionStrategy(
            strategy_id="t1204-aws-ssm-remote-commands",
            name="AWS SSM Session Manager Command Execution",
            description=(
                "Detect suspicious SSM Session Manager sessions where users may have been "
                "tricked into running malicious commands on EC2 instances via social "
                "engineering or fake IT support."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, eventName, userIdentity.arn, requestParameters.target, requestParameters.documentName
| filter eventSource = "ssm.amazonaws.com"
| filter eventName in ["StartSession", "SendCommand"]
| sort @timestamp desc''',
                terraform_template='''# AWS: Detect suspicious SSM command execution

variable "cloudtrail_log_group" { type = string }
variable "alert_email" { type = string }

# Step 1: Create SNS topic for SSM alerts
resource "aws_sns_topic" "ssm_alerts" {
  name         = "ssm-command-execution-alerts"
  display_name = "SSM Command Execution Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.ssm_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create metric filter for SSM sessions and commands
resource "aws_cloudwatch_log_metric_filter" "ssm_execution" {
  name           = "ssm-command-execution"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ ($.eventSource = \"ssm.amazonaws.com\") && (($.eventName = \"StartSession\") || ($.eventName = \"SendCommand\")) }"

  metric_transformation {
    name      = "SSMCommandExecutions"
    namespace = "Security/T1204"
    value     = "1"
  }
}

# Step 3: Create alarm for SSM command execution
resource "aws_cloudwatch_metric_alarm" "ssm_execution" {
  alarm_name          = "T1204-SSM-CommandExecution"
  alarm_description   = "Detects SSM Session Manager command executions"
  metric_name         = "SSMCommandExecutions"
  namespace           = "Security/T1204"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.ssm_alerts.arn]
}''',
                alert_severity="high",
                alert_title="AWS SSM: Remote Command Execution Detected",
                alert_description_template=(
                    "SSM Session Manager command executed by {userIdentity.arn}. "
                    "Target: {target}, Document: {documentName}. User may have been "
                    "socially engineered to run malicious commands."
                ),
                investigation_steps=[
                    "Review SSM session logs and command history",
                    "Verify the user who initiated the session",
                    "Check if commands match known malicious patterns",
                    "Review recent communication with the user for social engineering",
                    "Check for unusual command sequences or PowerShell/Bash execution",
                    "Verify target instances for compromise indicators"
                ],
                containment_actions=[
                    "Terminate active SSM sessions immediately",
                    "Disable SSM access for affected user",
                    "Isolate target instances in separate security group",
                    "Rotate credentials and session tokens",
                    "Review and restrict SSM Session Manager permissions",
                    "Implement session recording and command logging"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "SSM is used for legitimate administration; baseline normal users and "
                "command patterns, alert on deviations or unusual times"
            ),
            detection_coverage="70% - covers SSM Session Manager activity",
            evasion_considerations=(
                "Attackers may use legitimate maintenance windows or impersonate "
                "authorised administrators to blend in"
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled for SSM events", "SSM Session Manager configured"]
        ),

        DetectionStrategy(
            strategy_id="t1204-gcp-compute-ssh-browser",
            name="GCP Compute SSH-in-Browser Session Detection",
            description=(
                "Detect GCP Compute Engine SSH sessions initiated via browser where users "
                "may have been tricked into running malicious commands through social "
                "engineering or fake support scenarios."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="compute.instances.start"
OR protoPayload.methodName="compute.sshKeys.create"
OR protoPayload.serviceName="oslogin.googleapis.com"
OR resource.type="gce_instance"
AND protoPayload.request.metadata.items.key="enable-oslogin"''',
                gcp_terraform_template='''# GCP: Detect SSH-in-browser and remote command execution

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for SSH sessions
resource "google_logging_metric" "ssh_sessions" {
  name   = "gce-ssh-sessions"
  filter = <<-EOT
    (protoPayload.methodName="compute.instances.start"
    OR protoPayload.methodName="compute.sshKeys.create"
    OR protoPayload.serviceName="oslogin.googleapis.com")
    OR (resource.type="gce_instance"
    AND protoPayload.request.metadata.items.key="enable-oslogin")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy for SSH activity
resource "google_monitoring_alert_policy" "ssh_alert" {
  display_name = "GCE SSH Session Activity"
  combiner     = "OR"

  conditions {
    display_name = "SSH session or key creation detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ssh_sessions.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"  # 24 hours
  }
}''',
                alert_severity="medium",
                alert_title="GCP: SSH Session or Remote Access Detected",
                alert_description_template=(
                    "GCP Compute Engine SSH session or key creation detected. "
                    "User may have been socially engineered to enable remote access."
                ),
                investigation_steps=[
                    "Review Cloud Audit Logs for SSH session details",
                    "Verify the user who initiated the SSH connection",
                    "Check if OS Login keys were added unexpectedly",
                    "Review commands executed during the session if available",
                    "Check for unusual instance access patterns",
                    "Verify instance metadata for suspicious changes"
                ],
                containment_actions=[
                    "Revoke SSH keys for affected users",
                    "Stop suspicious instances to preserve state",
                    "Remove unauthorised metadata and SSH keys",
                    "Reset user credentials and disable accounts if compromised",
                    "Enable OS Login for centralised key management",
                    "Implement VPC firewall rules to restrict SSH access"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "SSH access is common for administration; baseline normal users and "
                "access patterns, focus on unusual times or unexpected users"
            ),
            detection_coverage="65% - covers GCE SSH and OS Login activity",
            evasion_considerations=(
                "Attackers may use legitimate credentials or blend in with normal "
                "administrative activity during business hours"
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled for Compute Engine"]
        ),

        DetectionStrategy(
            strategy_id="t1204-gcp-cloud-shell",
            name="GCP Cloud Shell Suspicious Command Execution",
            description=(
                "Detect suspicious commands executed via GCP Cloud Shell where users may "
                "have been tricked into running malicious scripts via fake CAPTCHA pages, "
                "copy-paste attacks, or IT impersonation."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="cloud_shell"
protoPayload.methodName="google.cloudshell.v1.CloudShellService.StartEnvironment"
OR protoPayload.methodName="google.cloudshell.v1.CloudShellService.AddPublicKey"''',
                gcp_terraform_template='''# GCP: Detect suspicious Cloud Shell activity

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for Cloud Shell usage
resource "google_logging_metric" "cloud_shell_activity" {
  name   = "cloud-shell-suspicious-activity"
  filter = <<-EOT
    resource.type="cloud_shell"
    AND (protoPayload.methodName="google.cloudshell.v1.CloudShellService.StartEnvironment"
    OR protoPayload.methodName="google.cloudshell.v1.CloudShellService.AddPublicKey")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy for Cloud Shell activity
resource "google_monitoring_alert_policy" "cloud_shell_alert" {
  display_name = "Cloud Shell Suspicious Activity"
  combiner     = "OR"

  conditions {
    display_name = "Cloud Shell session or key addition"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.cloud_shell_activity.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "43200s"  # 12 hours
  }

  documentation {
    content = "Cloud Shell activity detected. Verify user was not tricked into running malicious commands."
  }
}''',
                alert_severity="medium",
                alert_title="GCP: Cloud Shell Activity Detected",
                alert_description_template=(
                    "Cloud Shell session started or SSH key added. User may have been "
                    "socially engineered to execute malicious commands via copy-paste or "
                    "fake CAPTCHA pages."
                ),
                investigation_steps=[
                    "Review Cloud Shell session logs for executed commands",
                    "Check if user recently visited suspicious websites",
                    "Look for Base64-encoded commands or obfuscated scripts",
                    "Verify if user received instructions to paste commands",
                    "Check for unusual API calls made during the session",
                    "Review user's recent browser activity if available"
                ],
                containment_actions=[
                    "Disable Cloud Shell access for affected user",
                    "Revoke OAuth tokens and session credentials",
                    "Remove any SSH keys added during suspicious sessions",
                    "Reset user password and require re-authentication",
                    "Review and restrict Cloud Shell permissions organisation-wide",
                    "Implement user training on copy-paste attack risks"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Cloud Shell usage is legitimate for administration; focus on unusual "
                "users, off-hours access, or multiple rapid sessions"
            ),
            detection_coverage="75% - covers Cloud Shell sessions and key additions",
            evasion_considerations=(
                "Attackers may time their social engineering during business hours "
                "to blend with legitimate administrative activity"
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"]
        ),

        DetectionStrategy(
            strategy_id="t1204-gcp-container-execution",
            name="GCP Cloud Run Suspicious Container Execution",
            description=(
                "Detect Cloud Run container deployments and executions where users may "
                "have been tricked into deploying malicious container images from untrusted "
                "sources or executing malicious code in serverless containers."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="run.googleapis.com"
AND (protoPayload.methodName="google.cloud.run.v1.Services.CreateService"
OR protoPayload.methodName="google.cloud.run.v1.Services.ReplaceService")
AND protoPayload.request.spec.template.spec.containers.image!~"gcr.io/${PROJECT_ID}/"''',
                gcp_terraform_template='''# GCP: Detect suspicious Cloud Run container deployments

variable "project_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for external container images
resource "google_logging_metric" "external_containers" {
  name   = "cloud-run-external-images"
  filter = <<-EOT
    protoPayload.serviceName="run.googleapis.com"
    AND (protoPayload.methodName="google.cloud.run.v1.Services.CreateService"
    OR protoPayload.methodName="google.cloud.run.v1.Services.ReplaceService")
    AND NOT protoPayload.request.spec.template.spec.containers.image=~"gcr.io/${var.project_id}/"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy for external container usage
resource "google_monitoring_alert_policy" "external_container_alert" {
  display_name = "Cloud Run External Container Image"
  combiner     = "OR"

  conditions {
    display_name = "External or unapproved container image deployed"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.external_containers.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"  # 24 hours
  }

  documentation {
    content = <<-EOT
      Cloud Run service deployed with external container image.
      Verify the image source and user was not tricked into deploying malicious container.
    EOT
  }
}''',
                alert_severity="high",
                alert_title="GCP: Cloud Run External Container Deployed",
                alert_description_template=(
                    "Cloud Run service deployed with external container image. "
                    "User may have been tricked into deploying malicious container from "
                    "untrusted registry or public repository."
                ),
                investigation_steps=[
                    "Identify the container image source and registry",
                    "Review container image for malicious code or backdoors",
                    "Verify the user who deployed the service",
                    "Check Cloud Run service configuration and IAM permissions",
                    "Review container execution logs for suspicious behaviour",
                    "Scan container image with vulnerability scanning tools"
                ],
                containment_actions=[
                    "Delete suspicious Cloud Run services immediately",
                    "Block unapproved container registries via Organisation Policy",
                    "Require Binary Authorisation for container deployments",
                    "Rotate credentials used to deploy the service",
                    "Review and restrict Cloud Run deployment permissions",
                    "Implement container image scanning in CI/CD pipeline"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning=(
                "Some teams legitimately use external registries; maintain approved "
                "registry list and alert on deviations"
            ),
            detection_coverage="70% - covers Cloud Run deployments with external images",
            evasion_considerations=(
                "Attackers may use deceptive image names that appear to be from "
                "trusted sources or mirror legitimate images"
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled for Cloud Run"]
        )
    ],

    recommended_order=[
        "t1204-aws-ssm-remote-commands",
        "t1204-gcp-cloud-shell",
        "t1204-aws-instance-user-data",
        "t1204-gcp-container-execution",
        "t1204-gcp-compute-ssh-browser",
        "t1204-aws-lambda-external-trigger"
    ],
    total_effort_hours=6.5,
    coverage_improvement="+25% improvement for Execution tactic"
)
