"""
T1528 - Steal Application Access Token

Adversaries steal OAuth tokens, service account keys, or application
credentials to access cloud resources. This was a key technique in
the 2024 Snowflake breaches.
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
    technique_id="T1528",
    technique_name="Steal Application Access Token",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1528/",
    threat_context=ThreatContext(
        description=(
            "Adversaries steal OAuth tokens, API keys, or service account credentials "
            "to impersonate applications and access cloud resources. These tokens often "
            "have broad permissions and long lifetimes."
        ),
        attacker_goal="Steal OAuth/API tokens to access cloud resources as a legitimate application",
        why_technique=[
            "OAuth tokens bypass MFA requirements",
            "Service account keys often have elevated permissions",
            "Tokens may have long expiry times",
            "Applications often store tokens insecurely",
            "Token reuse from multiple locations is common",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Token theft bypasses traditional authentication controls. "
            "Tokens often have broad permissions and can access sensitive data. "
            "The Snowflake breaches showed massive impact potential."
        ),
        business_impact=[
            "Unauthorised access to cloud applications",
            "Data exfiltration without triggering MFA",
            "Persistent access until token rotation",
            "Compliance violations and breach notifications",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1530", "T1537", "T1078.004"],
        often_follows=["T1566", "T1190"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Cognito Token Anomalies
        DetectionStrategy(
            strategy_id="t1528-aws-cognito",
            name="Cognito Token Anomaly Detection",
            description="Detect suspicious token usage patterns in AWS Cognito.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, sourceIPAddress, userIdentity.principalId
| filter eventSource = "cognito-idp.amazonaws.com"
| filter eventName in ["InitiateAuth", "RespondToAuthChallenge", "GetUser"]
| stats count(*) as auth_count by sourceIPAddress, bin(1h)
| filter auth_count > 50
| sort auth_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect OAuth token anomalies

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
                AWS:SourceAccount: !Ref AWS::AccountId

  # Step 2: Metric filter for auth spikes
  AuthSpikeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "cognito-idp.amazonaws.com" && $.eventName = "InitiateAuth" }'
      MetricTransformations:
        - MetricName: CognitoAuthAttempts
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  AuthSpikeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: CognitoAuthSpike
      MetricName: CognitoAuthAttempts
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 500
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect OAuth token anomalies

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

data "aws_caller_identity" "current" {}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "oauth-anomaly-alerts"
  kms_master_key_id = "alias/aws/sns"
}

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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "cognito_auth" {
  name           = "cognito-auth-attempts"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"cognito-idp.amazonaws.com\" && $.eventName = \"InitiateAuth\" }"

  metric_transformation {
    name      = "CognitoAuthAttempts"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "auth_spike" {
  alarm_name          = "CognitoAuthSpike"
  metric_name         = "CognitoAuthAttempts"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 500
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Unusual OAuth Token Activity",
                alert_description_template="High volume of authentication attempts detected from {sourceIPAddress}.",
                investigation_steps=[
                    "Review source IPs for auth requests",
                    "Check if tokens used from new locations",
                    "Verify if legitimate application activity",
                    "Review app client configurations",
                ],
                containment_actions=[
                    "Revoke suspicious tokens",
                    "Rotate app client secrets",
                    "Enable advanced security features in Cognito",
                    "Review OAuth app permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known automation and CI/CD pipelines",
            detection_coverage="70% - volume-based detection",
            evasion_considerations="Slow token abuse may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail logging Cognito events"],
        ),
        # Strategy 2: AWS - API Key Usage Anomalies
        DetectionStrategy(
            strategy_id="t1528-aws-apikey",
            name="API Gateway Key Abuse Detection",
            description="Detect stolen API keys being used from unusual locations.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, ip, apiKey, status
| filter status >= 400
| stats count(*) as error_count by ip, apiKey, bin(1h)
| filter error_count > 100
| sort error_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect API key abuse

Parameters:
  APIGatewayLogGroup:
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
                AWS:SourceAccount: !Ref AWS::AccountId

  # Step 2: Metric filter for API errors
  APIErrorFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref APIGatewayLogGroup
      FilterPattern: '[..., status >= 400]'
      MetricTransformations:
        - MetricName: APIErrors
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm
  APIAbuseAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: APIKeyAbuse
      MetricName: APIErrors
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 500
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect API key abuse

variable "api_gateway_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

data "aws_caller_identity" "current" {}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "apikey-abuse-alerts"
  kms_master_key_id = "alias/aws/sns"
}

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
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter
resource "aws_cloudwatch_log_metric_filter" "api_errors" {
  name           = "api-errors"
  log_group_name = var.api_gateway_log_group
  pattern        = "[..., status >= 400]"

  metric_transformation {
    name      = "APIErrors"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm
resource "aws_cloudwatch_metric_alarm" "api_abuse" {
  alarm_name          = "APIKeyAbuse"
  metric_name         = "APIErrors"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 500
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="API Key Abuse Detected",
                alert_description_template="High error rate using API key from {ip}.",
                investigation_steps=[
                    "Identify which API key is being abused",
                    "Check source IPs for unusual geolocations",
                    "Review API access patterns",
                    "Verify key ownership and usage",
                ],
                containment_actions=[
                    "Rotate the affected API key",
                    "Add IP allowlist to API Gateway",
                    "Enable WAF rate limiting",
                    "Review API key permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal error rates per client",
            detection_coverage="65% - error-based detection",
            evasion_considerations="Successful stolen key use won't trigger",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["API Gateway access logging enabled"],
        ),
        # Strategy 3: GCP - Service Account Key Usage
        DetectionStrategy(
            strategy_id="t1528-gcp-sa-key",
            name="GCP Service Account Key Monitoring",
            description="Detect service account keys used from unusual locations.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.authenticationInfo.principalEmail:"-compute@"
protoPayload.authenticationInfo.serviceAccountKeyName!=""
protoPayload.requestMetadata.callerIp!~"^(10\\.|172\\.|192\\.168)"''',
                gcp_terraform_template="""# GCP: Monitor service account key usage

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

# Step 2: Log-based metric for SA key usage
resource "google_logging_metric" "sa_key_external" {
  name   = "external-sa-key-usage"
  filter = <<-EOT
    protoPayload.authenticationInfo.serviceAccountKeyName!=""
    protoPayload.requestMetadata.callerIp!~"^(10\\.|172\\.|192\\.168|35\\.)"
    severity>=NOTICE
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "sa_key_alert" {
  display_name = "External SA Key Usage"
  combiner     = "OR"

  conditions {
    display_name = "SA key used from external IP"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_key_external.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="Service Account Key Used Externally",
                alert_description_template="Service account key used from external IP address.",
                investigation_steps=[
                    "Identify which service account key was used",
                    "Review the source IP geolocation",
                    "Check what actions were performed",
                    "Verify if legitimate external access",
                ],
                containment_actions=[
                    "Delete and rotate the service account key",
                    "Review service account permissions",
                    "Enable VPC Service Controls",
                    "Audit all actions taken with the key",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known external CI/CD IPs",
            detection_coverage="80% - catches external key usage",
            evasion_considerations="Attacker using GCP-internal IPs",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 4: GCP - OAuth Token Abuse
        DetectionStrategy(
            strategy_id="t1528-gcp-oauth",
            name="GCP OAuth Token Anomaly Detection",
            description="Detect OAuth tokens used from multiple locations.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="audited_resource"
protoPayload.methodName=~"oauth2.*"
OR protoPayload.serviceName="iap.googleapis.com"''',
                gcp_terraform_template="""# GCP: Detect OAuth token anomalies

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

# Step 2: Log-based metric
resource "google_logging_metric" "oauth_anomalies" {
  name   = "oauth-token-anomalies"
  filter = <<-EOT
    resource.type="audited_resource"
    protoPayload.methodName=~"oauth2.*"
    severity>=WARNING
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "oauth_alert" {
  display_name = "OAuth Token Anomalies"
  combiner     = "OR"

  conditions {
    display_name = "Unusual OAuth activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.oauth_anomalies.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: OAuth Token Anomaly",
                alert_description_template="Unusual OAuth token activity detected.",
                investigation_steps=[
                    "Review OAuth consent logs",
                    "Check for new OAuth app authorisations",
                    "Verify token source locations",
                    "Review workspace admin logs",
                ],
                containment_actions=[
                    "Revoke suspicious OAuth app access",
                    "Remove unauthorised OAuth apps",
                    "Enable OAuth app restrictions",
                    "Review third-party app access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal OAuth patterns",
            detection_coverage="70% - anomaly-based detection",
            evasion_considerations="Legitimate-looking token patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1528-gcp-sa-key",
        "t1528-aws-cognito",
        "t1528-gcp-oauth",
        "t1528-aws-apikey",
    ],
    total_effort_hours=6.0,
    coverage_improvement="+18% improvement for Credential Access tactic",
)
