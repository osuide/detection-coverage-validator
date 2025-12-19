"""
T1555 - Credentials from Password Stores

Adversaries search common password storage locations to obtain user credentials.
Used by APT29, APT33, APT39, APT41, Volt Typhoon, and others.
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
    technique_id="T1555",
    technique_name="Credentials from Password Stores",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1555/",

    threat_context=ThreatContext(
        description=(
            "Adversaries search common password storage locations to obtain user credentials. "
            "Passwords are stored across systems depending on the operating system or application, "
            "including password managers and cloud secrets vaults. In cloud environments, this includes "
            "AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, browser credential stores on "
            "EC2/GCE instances, and credentials cached in container orchestration platforms. "
            "Once obtained, credentials enable lateral movement and access to restricted information."
        ),
        attacker_goal="Extract stored credentials from password managers and secret stores to enable lateral movement",
        why_technique=[
            "Centralized password stores contain high-value credentials",
            "Cloud secrets managers store database passwords, API keys, and service credentials",
            "Browser password stores on cloud instances often contain admin credentials",
            "Service account credentials in Kubernetes secrets enable cross-service access",
            "Successful credential extraction provides immediate access to multiple systems",
            "Less likely to trigger alerts compared to brute force attacks"
        ],
        known_threat_actors=[
            "APT29", "APT33", "APT34", "APT39", "APT41", "Evilnum",
            "FIN6", "HEXANE", "Leafminer", "MuddyWater", "Stealth Falcon",
            "Volt Typhoon", "Malteiro"
        ],
        recent_campaigns=[
            Campaign(
                name="APT29 SolarWinds Compromise",
                year=2020,
                description="APT29 attempted to access Group Managed Service Account (gMSA) passwords during the SolarWinds breach to enable lateral movement across enterprise environments",
                reference_url="https://attack.mitre.org/groups/G0016/"
            ),
            Campaign(
                name="Volt Typhoon Credential Harvesting",
                year=2023,
                description="Volt Typhoon attempted to obtain credentials from OpenSSH, RealVNC, and PuTTY password stores on compromised systems to maintain persistent access",
                reference_url="https://attack.mitre.org/groups/G1017/"
            ),
            Campaign(
                name="APT33 LaZagne Deployment",
                year=2024,
                description="APT33 utilised publicly available tools like LaZagne to gather credentials from password stores on compromised cloud infrastructure",
                reference_url="https://attack.mitre.org/groups/G0064/"
            ),
            Campaign(
                name="APT39 FTP Credential Theft",
                year=2024,
                description="APT39 deployed SmartFTP Password Decryptor to extract FTP passwords from compromised systems enabling access to file transfer infrastructure",
                reference_url="https://attack.mitre.org/groups/G0087/"
            )
        ],
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Credentials from password stores are high-value targets. In cloud environments, "
            "secrets managers contain database passwords, API keys, and service credentials that "
            "provide direct access to critical resources. Browser credential stores on bastion hosts "
            "often contain administrative credentials. The technique is widely used by sophisticated "
            "threat actors and enables rapid lateral movement across cloud infrastructure."
        ),
        business_impact=[
            "Unauthorised access to databases and sensitive data stores",
            "Lateral movement across cloud resources using stolen credentials",
            "API key compromise enabling unauthorised cloud resource access",
            "Privilege escalation via stolen administrative credentials",
            "Data exfiltration using legitimate credentials",
            "Regulatory compliance violations for credential exposure"
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1021", "T1530", "T1537"],
        often_follows=["T1190", "T1133", "T1078.004"]
    ),

    detection_strategies=[
        # Strategy 1: AWS Secrets Manager & Parameter Store Access
        DetectionStrategy(
            strategy_id="t1555-aws-secrets-access",
            name="AWS Secrets Manager Access Monitoring",
            description="Detect access to AWS Secrets Manager and SSM Parameter Store, particularly unusual or bulk access patterns that may indicate credential harvesting.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.secretsmanager", "aws.ssm"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "GetSecretValue", "BatchGetSecretValue",
                            "GetParameter", "GetParameters", "GetParametersByPath"
                        ]
                    }
                },
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor access to password stores and secrets

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Create SNS topic for alerts
  PasswordStoreAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: Password Store Access Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for secrets access
  SecretsAccessRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1555-PasswordStoreAccess
      Description: Alert on password store access
      EventPattern:
        source:
          - aws.secretsmanager
          - aws.ssm
        detail-type:
          - AWS API Call via CloudTrail
        detail:
          eventName:
            - GetSecretValue
            - BatchGetSecretValue
            - GetParameter
            - GetParameters
            - GetParametersByPath
      State: ENABLED
      Targets:
        - Id: AlertTopic
          Arn: !Ref PasswordStoreAlertTopic

  # Step 3: Grant EventBridge permission to publish to SNS
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref PasswordStoreAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref PasswordStoreAlertTopic''',
                terraform_template='''# Monitor access to password stores and secrets

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "password_store_alerts" {
  name         = "password-store-access-alerts"
  display_name = "Password Store Access Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.password_store_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for secrets access
resource "aws_cloudwatch_event_rule" "secrets_access" {
  name        = "T1555-PasswordStoreAccess"
  description = "Alert on password store access"
  event_pattern = jsonencode({
    source = ["aws.secretsmanager", "aws.ssm"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "GetSecretValue", "BatchGetSecretValue",
        "GetParameter", "GetParameters", "GetParametersByPath"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.secrets_access.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.password_store_alerts.arn
}

# Step 3: Grant EventBridge permission to publish to SNS
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.password_store_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.password_store_alerts.arn
    }]
  })
}''',
                alert_severity="high",
                alert_title="Password Store Access Detected",
                alert_description_template="Secret or parameter accessed: {secretId}. Principal: {userIdentity.arn}. Source IP: {sourceIPAddress}.",
                investigation_steps=[
                    "Verify the access was authorised and expected",
                    "Identify the principal accessing the password store",
                    "Review which secrets or parameters were accessed",
                    "Check the source IP address and location",
                    "Examine access patterns for bulk retrieval behaviour",
                    "Review CloudTrail logs for subsequent API calls using retrieved credentials"
                ],
                containment_actions=[
                    "Rotate the accessed secrets immediately if unauthorised",
                    "Revoke the principal's credentials if compromised",
                    "Review and restrict IAM policies granting secrets access",
                    "Enable resource-based policies on sensitive secrets",
                    "Implement VPC endpoints for Secrets Manager to restrict network access",
                    "Enable automatic secret rotation where applicable"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known applications and deployment pipelines that legitimately access secrets",
            detection_coverage="95% - catches all API-based secret access",
            evasion_considerations="Cannot evade if using AWS APIs; however, attackers with instance access could read from application memory",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"]
        ),

        # Strategy 2: Bulk Secrets Access Pattern Detection
        DetectionStrategy(
            strategy_id="t1555-bulk-secrets",
            name="Bulk Password Store Access Detection",
            description="Detect unusual patterns of bulk access to password stores that may indicate credential harvesting attempts.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.arn, eventName, requestParameters.secretId, sourceIPAddress
| filter eventSource in ["secretsmanager.amazonaws.com", "ssm.amazonaws.com"]
| filter eventName in ["GetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath"]
| stats count() as access_count, count_distinct(coalesce(requestParameters.secretId, requestParameters.name)) as unique_secrets
  by userIdentity.arn, sourceIPAddress, bin(10m)
| filter access_count > 10 or unique_secrets > 5
| sort access_count desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on bulk password store access patterns

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic
  BulkAccessAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for bulk secrets access
  BulkSecretsFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventSource = "secretsmanager.amazonaws.com" && $.eventName = "GetSecretValue") || ($.eventSource = "ssm.amazonaws.com" && $.eventName = "GetParameter") }'
      MetricTransformations:
        - MetricName: BulkPasswordStoreAccess
          MetricNamespace: Security/T1555
          MetricValue: "1"

  # Step 3: Alarm for excessive access
  BulkAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1555-BulkPasswordStoreAccess
      AlarmDescription: Bulk access to password stores detected
      MetricName: BulkPasswordStoreAccess
      Namespace: Security/T1555
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref BulkAccessAlertTopic''',
                terraform_template='''# Alert on bulk password store access patterns

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "bulk_access_alerts" {
  name = "bulk-password-store-access-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.bulk_access_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for bulk secrets access
resource "aws_cloudwatch_log_metric_filter" "bulk_secrets" {
  name           = "bulk-password-store-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventSource = \"secretsmanager.amazonaws.com\" && $.eventName = \"GetSecretValue\") || ($.eventSource = \"ssm.amazonaws.com\" && $.eventName = \"GetParameter\") }"

  metric_transformation {
    name      = "BulkPasswordStoreAccess"
    namespace = "Security/T1555"
    value     = "1"
  }
}

# Step 3: Alarm for excessive access
resource "aws_cloudwatch_metric_alarm" "bulk_access" {
  alarm_name          = "T1555-BulkPasswordStoreAccess"
  alarm_description   = "Bulk access to password stores detected"
  metric_name         = "BulkPasswordStoreAccess"
  namespace           = "Security/T1555"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.bulk_access_alerts.arn]
}''',
                alert_severity="critical",
                alert_title="Bulk Password Store Access Detected",
                alert_description_template="High volume of password store access detected. Principal: {principal}. {access_count} accesses in 10 minutes. {unique_secrets} unique secrets accessed.",
                investigation_steps=[
                    "Identify the IAM principal performing bulk access",
                    "Determine if the access pattern matches normal application behaviour",
                    "List all secrets and parameters accessed",
                    "Check if the source IP is expected for this principal",
                    "Review subsequent API calls to identify how credentials were used",
                    "Search for lateral movement attempts following credential access"
                ],
                containment_actions=[
                    "Immediately revoke the accessing principal's credentials",
                    "Rotate all accessed secrets and parameters",
                    "Review and restrict IAM policies granting bulk secrets access",
                    "Implement resource-based policies requiring additional authentication",
                    "Enable MFA requirements for sensitive secrets access",
                    "Configure VPC endpoints to restrict access to on-premises network only"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal access patterns; exclude deployment and backup systems with documented business justification",
            detection_coverage="80% - catches bulk credential harvesting",
            evasion_considerations="Slow, distributed access over extended periods may evade thresholds",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "CloudTrail logs sent to CloudWatch"]
        ),

        # Strategy 3: Browser Credential Store Access on EC2
        DetectionStrategy(
            strategy_id="t1555-browser-creds",
            name="Browser Password Store Access Detection",
            description="Detect access to browser credential stores on EC2 instances, particularly targeting Chrome, Firefox, and Edge password databases.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, @message, instanceId, processName, commandLine
| filter @message like /Login Data|key4.db|Cookies|logins.json|passwords.db|Chrome.*User Data|Firefox.*Profiles/
| filter @message like /sqlite3|python|powershell|cmd.exe|bash/
| stats count() as access_attempts by instanceId, processName, bin(5m)
| filter access_attempts > 0
| sort @timestamp desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect browser password store access on EC2 instances

Parameters:
  CloudWatchLogGroup:
    Type: String
    Description: Log group containing instance logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic
  BrowserCredAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for browser password database access
  BrowserPasswordFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudWatchLogGroup
      FilterPattern: '[time, instance, process, msg="*Login Data*" || msg="*key4.db*" || msg="*logins.json*" || msg="*passwords.db*"]'
      MetricTransformations:
        - MetricName: BrowserPasswordAccess
          MetricNamespace: Security/T1555
          MetricValue: "1"

  # Step 3: Alarm on browser credential access
  BrowserCredAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1555-BrowserPasswordStoreAccess
      AlarmDescription: Browser password store access detected
      MetricName: BrowserPasswordAccess
      Namespace: Security/T1555
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref BrowserCredAlertTopic''',
                terraform_template='''# Detect browser password store access on EC2 instances

variable "cloudwatch_log_group" {
  type        = string
  description = "Log group containing instance logs"
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "browser_cred_alerts" {
  name = "browser-password-access-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.browser_cred_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for browser password database access
resource "aws_cloudwatch_log_metric_filter" "browser_passwords" {
  name           = "browser-password-store-access"
  log_group_name = var.cloudwatch_log_group
  pattern        = "[time, instance, process, msg=\"*Login Data*\" || msg=\"*key4.db*\" || msg=\"*logins.json*\" || msg=\"*passwords.db*\"]"

  metric_transformation {
    name      = "BrowserPasswordAccess"
    namespace = "Security/T1555"
    value     = "1"
  }
}

# Step 3: Alarm on browser credential access
resource "aws_cloudwatch_metric_alarm" "browser_cred_access" {
  alarm_name          = "T1555-BrowserPasswordStoreAccess"
  alarm_description   = "Browser password store access detected"
  metric_name         = "BrowserPasswordAccess"
  namespace           = "Security/T1555"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.browser_cred_alerts.arn]
}''',
                alert_severity="high",
                alert_title="Browser Password Store Access Detected",
                alert_description_template="Access to browser password database detected on instance {instance_id}. Process: {process_name}. Command: {command_line}.",
                investigation_steps=[
                    "Identify which instance and user accessed browser credentials",
                    "Review the process that accessed password databases",
                    "Check if legitimate administrative activity was occurring",
                    "Search for exfiltration of password database files",
                    "Review recent logins and user sessions on the instance",
                    "Check for presence of credential dumping tools (LaZagne, ChromePass, etc.)"
                ],
                containment_actions=[
                    "Isolate the affected instance from the network",
                    "Rotate all credentials that may have been stored in the browser",
                    "Remove browser password databases from the instance",
                    "Review and disable browser password storage via GPO/configuration",
                    "Force password reset for users with sessions on the instance",
                    "Scan for malware and credential harvesting tools"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised backup and migration tools; exclude browser update processes",
            detection_coverage="70% - detects file-based browser credential access",
            evasion_considerations="In-memory credential extraction may not generate file access logs",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1.5 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudWatch Logs Agent installed", "File access logging enabled"]
        ),

        # Strategy 4: GCP Secret Manager Access
        DetectionStrategy(
            strategy_id="t1555-gcp-secrets",
            name="GCP Secret Manager Access Detection",
            description="Monitor access to GCP Secret Manager to detect credential harvesting attempts.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"
OR protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.GetSecretVersion"''',
                gcp_terraform_template='''# GCP: Monitor Secret Manager access

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Password Store Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log-based metric for secret access
resource "google_logging_metric" "secret_access" {
  project = var.project_id
  name    = "secret-manager-access"
  filter  = <<-EOT
    protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"
    OR protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.GetSecretVersion"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal accessing secrets"
    }
  }

  label_extractors = {
    principal = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Create alert policy
resource "google_monitoring_alert_policy" "secret_access" {
  project      = var.project_id
  display_name = "T1555: Secret Manager Access"
  combiner     = "OR"
  conditions {
    display_name = "Secret accessed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.secret_access.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "604800s"
  }
  documentation {
    content   = "Secret Manager access detected. Verify access was authorised and investigate if suspicious."
    mime_type = "text/markdown"
  }
}''',
                alert_severity="high",
                alert_title="GCP: Secret Manager Access Detected",
                alert_description_template="Secret accessed from Secret Manager. Principal: {principal}. Secret: {resource_name}.",
                investigation_steps=[
                    "Verify the access was authorised and expected",
                    "Identify the service account or user accessing the secret",
                    "Review which specific secrets were accessed",
                    "Check the source location (GCE instance, Cloud Function, etc.)",
                    "Examine access patterns for bulk retrieval behaviour",
                    "Review subsequent Cloud Audit Logs for credential usage"
                ],
                containment_actions=[
                    "Rotate the accessed secrets if unauthorised access detected",
                    "Revoke the service account key or disable the user account",
                    "Review and restrict IAM roles granting secretmanager.versions.access",
                    "Enable CMEK encryption for sensitive secrets",
                    "Implement VPC Service Controls to restrict secret access",
                    "Enable automatic secret rotation"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known service accounts used by applications",
            detection_coverage="95% - catches all Secret Manager API access",
            evasion_considerations="Cannot evade if using GCP APIs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"]
        ),

        # Strategy 5: Kubernetes Secrets Access
        DetectionStrategy(
            strategy_id="t1555-k8s-secrets",
            name="Kubernetes Secrets Access Detection",
            description="Detect unusual access to Kubernetes secrets in EKS or GKE clusters that may indicate credential harvesting.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query=r'''fields @timestamp, @message, kubernetes.pod_name, kubernetes.namespace_name
| filter @message like /\/run\/secrets\/kubernetes.io|KUBECTL.*get.*secrets|base64.*decode|env.*SECRET/
| stats count() as secret_access by kubernetes.pod_name, kubernetes.namespace_name, bin(10m)
| filter secret_access > 3
| sort @timestamp desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Kubernetes secrets access in EKS

Parameters:
  EKSLogGroup:
    Type: String
    Description: CloudWatch log group for EKS cluster
    Default: /aws/eks/cluster/logs
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic
  K8sSecretsAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for Kubernetes secrets access
  K8sSecretsFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref EKSLogGroup
      FilterPattern: '[time, stream, pod, msg="*/run/secrets*" || msg="*get secrets*" || msg="*base64*decode*"]'
      MetricTransformations:
        - MetricName: KubernetesSecretsAccess
          MetricNamespace: Security/T1555
          MetricValue: "1"

  # Step 3: Alarm on excessive secrets access
  K8sSecretsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1555-KubernetesSecretsAccess
      AlarmDescription: Unusual Kubernetes secrets access detected
      MetricName: KubernetesSecretsAccess
      Namespace: Security/T1555
      Statistic: Sum
      Period: 600
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref K8sSecretsAlertTopic''',
                terraform_template='''# Detect Kubernetes secrets access in EKS

variable "eks_log_group" {
  type        = string
  description = "CloudWatch log group for EKS cluster"
  default     = "/aws/eks/cluster/logs"
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "k8s_secrets_alerts" {
  name = "kubernetes-secrets-access-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.k8s_secrets_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for Kubernetes secrets access
resource "aws_cloudwatch_log_metric_filter" "k8s_secrets" {
  name           = "kubernetes-secrets-access"
  log_group_name = var.eks_log_group
  pattern        = "[time, stream, pod, msg=\"*/run/secrets*\" || msg=\"*get secrets*\" || msg=\"*base64*decode*\"]"

  metric_transformation {
    name      = "KubernetesSecretsAccess"
    namespace = "Security/T1555"
    value     = "1"
  }
}

# Step 3: Alarm on excessive secrets access
resource "aws_cloudwatch_metric_alarm" "k8s_secrets" {
  alarm_name          = "T1555-KubernetesSecretsAccess"
  alarm_description   = "Unusual Kubernetes secrets access detected"
  metric_name         = "KubernetesSecretsAccess"
  namespace           = "Security/T1555"
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.k8s_secrets_alerts.arn]
}''',
                alert_severity="high",
                alert_title="Kubernetes Secrets Access Detected",
                alert_description_template="Unusual access to Kubernetes secrets detected in pod {pod_name}. Namespace: {namespace}. {secret_access} access attempts in 10 minutes.",
                investigation_steps=[
                    "Identify the pod and container accessing Kubernetes secrets",
                    "Review the pod's service account and RBAC permissions",
                    "Check if the pod spec includes suspicious volume mounts",
                    "Examine the container image and its provenance",
                    "Review kubectl audit logs for secret enumeration",
                    "Check for lateral movement attempts using extracted credentials"
                ],
                containment_actions=[
                    "Delete the suspicious pod immediately",
                    "Rotate all Kubernetes secrets in the affected namespace",
                    "Review and restrict service account RBAC permissions",
                    "Enable Pod Security Admission to enforce restrictive policies",
                    "Update the container image if compromised",
                    "Implement network policies to restrict pod communication"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal secret access patterns for each application; exclude init containers that legitimately read secrets",
            detection_coverage="65% - covers common Kubernetes secret access patterns",
            evasion_considerations="In-memory credential extraction from environment variables may not generate logs",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-25",
            prerequisites=["EKS cluster with CloudWatch Container Insights", "Audit logging enabled"]
        )
    ],

    recommended_order=[
        "t1555-aws-secrets-access",
        "t1555-bulk-secrets",
        "t1555-gcp-secrets",
        "t1555-k8s-secrets",
        "t1555-browser-creds"
    ],
    total_effort_hours=5.5,
    coverage_improvement="+22% improvement for Credential Access tactic"
)
