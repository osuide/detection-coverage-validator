"""
T1552.001 - Unsecured Credentials: Credentials in Files

Adversaries search for credentials in files like .env, config files,
and code repositories. The 2024 AWS .env attack hit 230M+ environments.
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
    technique_id="T1552.001",
    technique_name="Unsecured Credentials: Credentials in Files",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1552/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries search compromised systems and web servers for files "
            "containing credentials. In cloud environments, .env files, config files, "
            "and source code often contain API keys, database passwords, and cloud credentials."
        ),
        attacker_goal="Obtain valid credentials from exposed configuration files",
        why_technique=[
            "Developers often store credentials in plaintext files",
            ".env files frequently exposed via misconfigured web servers",
            "Credentials found here often have excessive permissions",
            "No authentication required if files are publicly accessible",
            "Automated scanning makes large-scale discovery trivial",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "This was the #1 cloud attack vector in 2024. Exposed .env files "
            "led to massive breaches. Credentials often have admin privileges, "
            "enabling full environment compromise."
        ),
        business_impact=[
            "Full cloud environment compromise",
            "Data exfiltration at scale",
            "Cryptomining and resource abuse",
            "Regulatory fines for credential exposure",
            "Reputational damage",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1087.004", "T1530"],
        often_follows=["T1190", "T1595"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - GuardDuty for credential exfiltration
        DetectionStrategy(
            strategy_id="t1552001-aws-guardduty",
            name="GuardDuty Credential Exfiltration Detection",
            description="Detect when credentials obtained from files are used from external locations.",
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect credential exfiltration from files

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty
  Detector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true

  # Step 2: SNS for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route credential exfiltration findings
  CredentialExfilRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
            - prefix: "CredentialAccess:IAMUser"
      Targets:
        - Id: Alert
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
                terraform_template="""# Detect credential exfiltration from files

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 2: SNS for alerts
resource "aws_sns_topic" "alerts" {
  name = "credential-exfil-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route credential exfiltration findings
resource "aws_cloudwatch_event_rule" "cred_exfil" {
  name = "credential-exfil-alerts"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration" },
        { prefix = "CredentialAccess:IAMUser" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.cred_exfil.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.alerts.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Credential Exfiltration Detected",
                alert_description_template="Credentials used from external location. Finding: {finding_type}. Source IP: {source_ip}.",
                investigation_steps=[
                    "Identify the source of the credentials (which file/service)",
                    "Check CloudTrail for all API calls using these credentials",
                    "Determine what resources were accessed",
                    "Identify how the credentials were exposed",
                ],
                containment_actions=[
                    "Immediately rotate the compromised credentials",
                    "Revoke any active sessions",
                    "Block the source IP if known malicious",
                    "Scan for exposed .env files on web servers",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known CI/CD systems and deployment tools",
            detection_coverage="70% - catches credential use from unexpected locations",
            evasion_considerations="Attacker using credentials from expected regions/IPs",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4/million events",
            prerequisites=["GuardDuty enabled"],
        ),
        # Strategy 2: AWS - Detect .env file access via ALB/CloudFront
        DetectionStrategy(
            strategy_id="t1552001-aws-env-access",
            name="Detect .env File Access Attempts",
            description="Monitor for HTTP requests attempting to access .env files.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, @message
| filter @message like /\\.env/
| filter @message like /GET|POST|HEAD/
| stats count(*) as attempts by bin(1h)
| filter attempts > 10""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on .env file access attempts

Parameters:
  ALBLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for .env access
  EnvAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref ALBLogGroup
      FilterPattern: '".env"'
      MetricTransformations:
        - MetricName: EnvFileAccess
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm on threshold
  EnvAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: EnvFileAccessAttempts
      MetricName: EnvFileAccess
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Alert on .env file access attempts

variable "alb_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "env-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for .env access
resource "aws_cloudwatch_log_metric_filter" "env_access" {
  name           = "env-file-access"
  log_group_name = var.alb_log_group
  pattern        = "\".env\""

  metric_transformation {
    name      = "EnvFileAccess"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm on threshold
resource "aws_cloudwatch_metric_alarm" "env_access" {
  alarm_name          = "EnvFileAccessAttempts"
  metric_name         = "EnvFileAccess"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title=".env File Access Attempts Detected",
                alert_description_template="Multiple attempts to access .env files detected. {attempts} attempts in the last hour.",
                investigation_steps=[
                    "Review source IPs attempting access",
                    "Check if .env files are actually exposed",
                    "Verify web server configuration blocks sensitive files",
                    "Scan for credentials in version control",
                ],
                containment_actions=[
                    "Block malicious IPs at WAF/security group",
                    "Configure web server to deny access to .env files",
                    "Rotate any credentials that may have been exposed",
                    "Add .env to .gitignore if not already",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Threshold may need adjustment based on traffic",
            detection_coverage="90% - catches scanning attempts",
            evasion_considerations="Attackers may use different file names",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["ALB access logs enabled", "CloudWatch Logs configured"],
        ),
        # Strategy 3: GCP - Security Command Center + Cloud Logging
        DetectionStrategy(
            strategy_id="t1552001-gcp-logging",
            name="GCP Credential File Access Detection",
            description="Monitor for access to sensitive configuration files in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="http_load_balancer"
httpRequest.requestUrl=~".*\\.env.*"
OR httpRequest.requestUrl=~".*config\\.json.*"
OR httpRequest.requestUrl=~".*credentials.*"''',
                gcp_terraform_template="""# GCP: Alert on sensitive file access attempts

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for sensitive file access
resource "google_logging_metric" "sensitive_file_access" {
  name   = "sensitive-file-access"
  filter = <<-EOT
    resource.type="http_load_balancer"
    (httpRequest.requestUrl=~".*\\.env.*"
    OR httpRequest.requestUrl=~".*\\.config.*"
    OR httpRequest.requestUrl=~".*credentials.*")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "sensitive_file_alert" {
  display_name = "Sensitive File Access Attempts"
  combiner     = "OR"

  conditions {
    display_name = "High volume of sensitive file requests"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sensitive_file_access.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Sensitive File Access Detected",
                alert_description_template="Attempts to access sensitive configuration files detected via load balancer.",
                investigation_steps=[
                    "Review Cloud Audit Logs for source details",
                    "Check if application is exposing config files",
                    "Verify Cloud Storage bucket permissions",
                    "Scan GCE instances for exposed credential files",
                ],
                containment_actions=[
                    "Configure Cloud Armor to block requests for sensitive files",
                    "Rotate any potentially exposed service account keys",
                    "Review and restrict IAM permissions",
                    "Enable VPC Service Controls for sensitive projects",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust URL patterns based on application structure",
            detection_coverage="85% - catches HTTP-based scanning",
            evasion_considerations="Direct API access bypasses load balancer logs",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["HTTP(S) Load Balancer logging enabled"],
        ),
        # Strategy 4: AWS - Secrets Manager access anomaly
        DetectionStrategy(
            strategy_id="t1552001-aws-secrets-access",
            name="Unusual Secrets Manager Access",
            description="Detect unusual access patterns to AWS Secrets Manager.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, eventName, requestParameters.secretId
| filter eventSource = "secretsmanager.amazonaws.com"
| filter eventName in ["GetSecretValue", "BatchGetSecretValue"]
| stats count(*) as access_count by userIdentity.arn, bin(1h)
| filter access_count > 20
| sort access_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on unusual Secrets Manager access

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter
  SecretsAccessFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "secretsmanager.amazonaws.com" && $.eventName = "GetSecretValue" }'
      MetricTransformations:
        - MetricName: SecretsAccess
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  SecretsAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnusualSecretsAccess
      MetricName: SecretsAccess
      Namespace: Security
      Statistic: Sum
      Period: 3600
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Alert on unusual Secrets Manager access

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "secrets-access-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "secrets_access" {
  name           = "secrets-manager-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"secretsmanager.amazonaws.com\" && $.eventName = \"GetSecretValue\" }"

  metric_transformation {
    name      = "SecretsAccess"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "secrets_access" {
  alarm_name          = "UnusualSecretsAccess"
  metric_name         = "SecretsAccess"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unusual Secrets Manager Access",
                alert_description_template="High volume of Secrets Manager access detected. {access_count} accesses in 1 hour.",
                investigation_steps=[
                    "Identify which IAM principal is accessing secrets",
                    "Check if access pattern matches normal application behaviour",
                    "Review which secrets were accessed",
                    "Verify the source IP and user agent",
                ],
                containment_actions=[
                    "Rotate accessed secrets immediately",
                    "Restrict IAM permissions for the principal",
                    "Enable secret rotation if not already",
                    "Review resource policies on secrets",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal access patterns; exclude known batch processes",
            detection_coverage="80% - catches bulk credential access",
            evasion_considerations="Slow, distributed access may evade threshold",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "Logs in CloudWatch"],
        ),
    ],
    recommended_order=[
        "t1552001-aws-guardduty",
        "t1552001-aws-env-access",
        "t1552001-gcp-logging",
        "t1552001-aws-secrets-access",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+25% improvement for Credential Access tactic",
)
