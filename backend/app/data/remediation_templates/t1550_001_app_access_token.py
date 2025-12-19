"""
T1550.001 - Use Alternate Authentication Material: Application Access Token

Adversaries use stolen application access tokens to bypass normal authentication
and access cloud resources without needing passwords or MFA.
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
    technique_id="T1550.001",
    technique_name="Use Alternate Authentication Material: Application Access Token",
    tactic_ids=["TA0005", "TA0008"],
    mitre_url="https://attack.mitre.org/techniques/T1550/001/",

    threat_context=ThreatContext(
        description=(
            "Adversaries exploit stolen application access tokens to circumvent "
            "standard authentication mechanisms and gain unauthorised access to cloud "
            "resources. These tokens enable API access without requiring passwords or "
            "MFA, making them high-value targets for credential theft attacks."
        ),
        attacker_goal="Use stolen OAuth/API tokens to access cloud resources whilst bypassing authentication controls",
        why_technique=[
            "Tokens bypass password-based authentication and MFA",
            "OAuth tokens often have long validity periods",
            "Tokens can be reused from any location without triggering location-based alerts",
            "API access negates effectiveness of second authentication factors",
            "Service account tokens frequently have elevated permissions"
        ],
        known_threat_actors=["APT28", "APT29", "HAFNIUM"],
        recent_campaigns=[
            Campaign(
                name="APT28 Gmail OAuth Abuse",
                year=2022,
                description="APT28 deployed malicious OAuth applications targeting Gmail and Yahoo Mail accounts for intelligence collection",
                reference_url="https://attack.mitre.org/groups/G0007/"
            ),
            Campaign(
                name="HAFNIUM Exchange Server Attacks",
                year=2021,
                description="HAFNIUM abused compromised service principals with administrative permissions for data theft from Exchange servers",
                reference_url="https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
            ),
            Campaign(
                name="SolarWinds Supply Chain Attack",
                year=2020,
                description="APT29 used compromised service principals during the SolarWinds breach to modify Office 365 configurations",
                reference_url="https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/"
            )
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Token-based attacks bypass traditional authentication controls including MFA. "
            "Once stolen, tokens provide immediate access to cloud resources and APIs. "
            "The increasing use of OAuth and cloud services makes this technique highly relevant."
        ),
        business_impact=[
            "Unauthorised access to cloud applications without MFA",
            "Data exfiltration via legitimate API calls",
            "Persistent access until token expiration or rotation",
            "Lateral movement to connected cloud services",
            "Compliance violations due to bypassed authentication controls"
        ],
        typical_attack_phase="lateral_movement",
        often_precedes=["T1530", "T1537", "T1114"],
        often_follows=["T1528", "T1552", "T1566"]
    ),

    detection_strategies=[
        # Strategy 1: AWS - STS Token Anomalies
        DetectionStrategy(
            strategy_id="t1550001-aws-sts",
            name="AWS STS Token Usage Anomalies",
            description="Detect unusual AWS STS API calls that request temporary credentials with elevated privileges.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, requestParameters.durationSeconds
| filter eventSource = "sts.amazonaws.com"
| filter eventName in ["GetFederationToken", "AssumeRole", "GetSessionToken"]
| stats count(*) as token_requests, count_distinct(sourceIPAddress) as unique_ips by userIdentity.arn, bin(1h)
| filter token_requests > 20 or unique_ips > 3
| sort token_requests desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect STS token anomalies for T1550.001

Parameters:
  CloudTrailLogGroup:
    Type: String
  AlertEmail:
    Type: String

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for STS token requests
  STSTokenFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "sts.amazonaws.com" && ($.eventName = "GetFederationToken" || $.eventName = "AssumeRole" || $.eventName = "GetSessionToken") }'
      MetricTransformations:
        - MetricName: STSTokenRequests
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm for unusual token activity
  STSTokenAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: UnusualSTSTokenActivity
      MetricName: STSTokenRequests
      Namespace: Security
      Statistic: Sum
      Period: 3600
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]''',
                terraform_template='''# Detect STS token anomalies

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "sts-token-anomaly-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for STS token requests
resource "aws_cloudwatch_log_metric_filter" "sts_tokens" {
  name           = "sts-token-requests"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"sts.amazonaws.com\" && ($.eventName = \"GetFederationToken\" || $.eventName = \"AssumeRole\" || $.eventName = \"GetSessionToken\") }"

  metric_transformation {
    name      = "STSTokenRequests"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm for unusual token activity
resource "aws_cloudwatch_metric_alarm" "sts_anomaly" {
  alarm_name          = "UnusualSTSTokenActivity"
  metric_name         = "STSTokenRequests"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}''',
                alert_severity="high",
                alert_title="Unusual STS Token Activity",
                alert_description_template="High volume of STS token requests detected from {userIdentity.arn}. {token_requests} requests from {unique_ips} IP addresses.",
                investigation_steps=[
                    "Review CloudTrail for all STS API calls by the affected identity",
                    "Check source IP addresses for unusual geolocations",
                    "Verify if token requests match expected application behaviour",
                    "Review what actions were performed with issued tokens",
                    "Check for impossible travel scenarios"
                ],
                containment_actions=[
                    "Revoke active sessions using AWS STS",
                    "Rotate credentials for the affected identity",
                    "Review and restrict STS permissions via IAM policies",
                    "Enable MFA requirement for sensitive STS operations",
                    "Implement IP allowlisting for token requests"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known automation systems and CI/CD pipelines; adjust threshold based on normal token usage patterns",
            detection_coverage="70% - catches volume-based anomalies",
            evasion_considerations="Attackers may throttle token requests to evade volume thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail logging STS events to CloudWatch Logs"]
        ),

        # Strategy 2: AWS - OAuth Token Reuse Detection
        DetectionStrategy(
            strategy_id="t1550001-aws-oauth-reuse",
            name="OAuth Token Reuse from Multiple Locations",
            description="Detect when OAuth tokens are used from multiple geographic locations or user agents.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.principalId, sourceIPAddress, userAgent
| filter eventSource = "cognito-idp.amazonaws.com"
| filter eventName in ["InitiateAuth", "RespondToAuthChallenge", "GetUser", "GetUserAttributeVerificationCode"]
| stats count(*) as auth_count,
        count_distinct(sourceIPAddress) as ip_count,
        count_distinct(userAgent) as agent_count
  by userIdentity.principalId, bin(4h)
| filter ip_count > 2 or agent_count > 2
| sort auth_count desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect OAuth token reuse anomalies

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
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for Cognito auth from multiple IPs
  OAuthReuseFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "cognito-idp.amazonaws.com" && ($.eventName = "InitiateAuth" || $.eventName = "RespondToAuthChallenge") }'
      MetricTransformations:
        - MetricName: CognitoAuthAttempts
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm for token reuse
  TokenReuseAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: OAuthTokenReuse
      MetricName: CognitoAuthAttempts
      Namespace: Security
      Statistic: Sum
      Period: 14400
      Threshold: 50
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      AlarmActions: [!Ref AlertTopic]''',
                terraform_template='''# Detect OAuth token reuse anomalies

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "oauth-token-reuse-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for Cognito auth
resource "aws_cloudwatch_log_metric_filter" "oauth_reuse" {
  name           = "oauth-token-reuse"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"cognito-idp.amazonaws.com\" && ($.eventName = \"InitiateAuth\" || $.eventName = \"RespondToAuthChallenge\") }"

  metric_transformation {
    name      = "CognitoAuthAttempts"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm for token reuse
resource "aws_cloudwatch_metric_alarm" "token_reuse" {
  alarm_name          = "OAuthTokenReuse"
  metric_name         = "CognitoAuthAttempts"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 14400
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}''',
                alert_severity="high",
                alert_title="OAuth Token Used from Multiple Locations",
                alert_description_template="Token for {userIdentity.principalId} used from {ip_count} different IP addresses and {agent_count} user agents.",
                investigation_steps=[
                    "Identify all source IPs and geolocate them",
                    "Review user agent strings for suspicious patterns",
                    "Check if legitimate for user to access from multiple locations",
                    "Review all API calls made with the token",
                    "Correlate with other security events for the user"
                ],
                containment_actions=[
                    "Revoke the OAuth token immediately",
                    "Force user re-authentication with MFA",
                    "Enable token binding if supported",
                    "Review and restrict OAuth application permissions",
                    "Implement context-aware access controls"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Consider legitimate use cases like VPN users or mobile workers; whitelist known corporate IP ranges",
            detection_coverage="65% - detects token reuse patterns",
            evasion_considerations="Attackers using tokens from expected geographic regions",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail logging Cognito events"]
        ),

        # Strategy 3: GCP - Service Account Token Abuse
        DetectionStrategy(
            strategy_id="t1550001-gcp-sa-token",
            name="GCP Service Account Token Abuse Detection",
            description="Detect service account tokens used from unauthorised locations or with unusual patterns.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.authenticationInfo.principalEmail=~".*@.*iam.gserviceaccount.com"
protoPayload.requestMetadata.callerIp!~"^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|35\\.)"
severity>=NOTICE''',
                gcp_terraform_template='''# GCP: Detect service account token abuse

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

# Step 2: Log-based metric for external SA token usage
resource "google_logging_metric" "sa_token_external" {
  name   = "external-sa-token-usage"
  filter = <<-EOT
    protoPayload.authenticationInfo.principalEmail=~".*@.*iam.gserviceaccount.com"
    protoPayload.requestMetadata.callerIp!~"^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|35\\.)"
    severity>=NOTICE
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for external token usage
resource "google_monitoring_alert_policy" "sa_token_alert" {
  display_name = "Service Account Token Used Externally"
  combiner     = "OR"

  conditions {
    display_name = "SA token from external IP"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_token_external.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Service account token detected in use from external IP address. This may indicate stolen credentials."
  }
}''',
                alert_severity="high",
                alert_title="Service Account Token Used from External Location",
                alert_description_template="Service account token used from external IP address. This may indicate credential theft.",
                investigation_steps=[
                    "Identify which service account token was used",
                    "Review the source IP address and geolocation",
                    "Check what API calls were made with the token",
                    "Verify if external access is legitimate",
                    "Review service account key creation/download logs"
                ],
                containment_actions=[
                    "Delete and rotate the service account key",
                    "Disable the service account if not actively needed",
                    "Review and reduce service account permissions",
                    "Enable VPC Service Controls to restrict access",
                    "Implement Workload Identity where possible"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known external services and CI/CD systems; exclude Google Cloud IP ranges",
            detection_coverage="75% - catches external token usage",
            evasion_considerations="Attackers using GCP-hosted infrastructure or VPN",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled"]
        ),

        # Strategy 4: GCP - OAuth Token Anomaly Detection
        DetectionStrategy(
            strategy_id="t1550001-gcp-oauth",
            name="GCP OAuth Token Anomaly Detection",
            description="Detect unusual OAuth token usage patterns including token reuse and consent anomalies.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="audited_resource"
(protoPayload.methodName=~"google.identity.*" OR protoPayload.serviceName="oauth2.googleapis.com")
severity>=WARNING''',
                gcp_terraform_template='''# GCP: Detect OAuth token anomalies

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

# Step 2: Log-based metric for OAuth anomalies
resource "google_logging_metric" "oauth_anomalies" {
  name   = "oauth-token-anomalies"
  filter = <<-EOT
    resource.type="audited_resource"
    (protoPayload.methodName=~"google.identity.*" OR protoPayload.serviceName="oauth2.googleapis.com")
    severity>=WARNING
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for OAuth anomalies
resource "google_monitoring_alert_policy" "oauth_alert" {
  display_name = "OAuth Token Anomalies Detected"
  combiner     = "OR"

  conditions {
    display_name = "Unusual OAuth activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.oauth_anomalies.name}\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content = "Unusual OAuth token activity detected. Review for potential token theft or abuse."
  }
}''',
                alert_severity="high",
                alert_title="GCP OAuth Token Anomalies",
                alert_description_template="Unusual OAuth token activity detected in GCP environment.",
                investigation_steps=[
                    "Review OAuth consent audit logs",
                    "Check for unauthorised third-party application authorisations",
                    "Verify token source IP addresses and locations",
                    "Review workspace admin activity logs",
                    "Check for scope escalation attempts"
                ],
                containment_actions=[
                    "Revoke suspicious OAuth application access",
                    "Remove unauthorised third-party applications",
                    "Enable OAuth app restrictions via workspace admin console",
                    "Review and limit OAuth scopes for applications",
                    "Implement context-aware access policies"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal OAuth patterns for your organisation; whitelist approved applications",
            detection_coverage="70% - detects anomalous OAuth behaviour",
            evasion_considerations="Legitimate-appearing OAuth flows that blend with normal activity",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled", "Admin Activity logs enabled"]
        )
    ],

    recommended_order=[
        "t1550001-aws-sts",
        "t1550001-gcp-sa-token",
        "t1550001-aws-oauth-reuse",
        "t1550001-gcp-oauth"
    ],
    total_effort_hours=6.5,
    coverage_improvement="+20% improvement for Defence Evasion and Lateral Movement tactics"
)
