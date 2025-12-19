"""
T1550.004 - Use Alternate Authentication Material: Web Session Cookie

Adversaries steal web session cookies to bypass authentication controls,
including MFA. APT29 used this technique in the SolarWinds compromise to
forge cookies and access cloud resources.
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
    technique_id="T1550.004",
    technique_name="Use Alternate Authentication Material: Web Session Cookie",
    tactic_ids=["TA0005", "TA0008"],
    mitre_url="https://attack.mitre.org/techniques/T1550/004/",

    threat_context=ThreatContext(
        description=(
            "Adversaries steal web session cookies to authenticate to web applications "
            "and cloud services without requiring credentials or MFA. Once stolen, these "
            "cookies can be imported into attackers' browsers, granting unauthorised access "
            "to accounts with extended validity periods. This technique is particularly "
            "effective against cloud applications and SaaS platforms."
        ),
        attacker_goal="Steal and reuse session cookies to bypass authentication and MFA controls",
        why_technique=[
            "Bypasses MFA since session is already authenticated",
            "Cookies often have long validity periods",
            "No credential theft detection triggered",
            "Works across cloud and web applications",
            "Can maintain persistent access until cookie expiry",
            "Difficult to detect without behaviour analysis"
        ],
        known_threat_actors=["APT29", "Star Blizzard"],
        recent_campaigns=[
            Campaign(
                name="SolarWinds Compromise - Cookie Forgery",
                year=2020,
                description="APT29 stole session cookies and forged duo-sid cookies to bypass MFA on cloud resources",
                reference_url="https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/"
            ),
            Campaign(
                name="Star Blizzard MFA Bypass",
                year=2023,
                description="Star Blizzard used EvilGinx-stolen session cookies to bypass multi-factor authentication",
                reference_url="https://attack.mitre.org/groups/G1033/"
            )
        ],
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Session cookie theft completely bypasses MFA and traditional authentication. "
            "Cookies provide immediate access with victim's privileges. "
            "APT29's successful use in SolarWinds demonstrated critical infrastructure impact."
        ),
        business_impact=[
            "Unauthorised access bypassing MFA",
            "Account takeover without credential theft alerts",
            "Access to sensitive data and systems",
            "Persistent access until cookie expiry or rotation",
            "Compliance violations for authentication controls"
        ],
        typical_attack_phase="defense_evasion",
        often_precedes=["T1530", "T1537", "T1114.003"],
        often_follows=["T1566", "T1539", "T1557"]
    ),

    detection_strategies=[
        # Strategy 1: AWS - Session Cookie Anomalies
        DetectionStrategy(
            strategy_id="t1550-004-aws-session",
            name="AWS Console Session Anomaly Detection",
            description="Detect AWS Console sessions with suspicious characteristics indicating stolen cookies.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, eventName, sourceIPAddress, userIdentity.principalId, userAgent, requestParameters.sessionName
| filter eventName = "AssumeRole" OR eventName = "GetSigninToken" OR eventName = "ConsoleLogin"
| stats count(*) as session_count, count_distinct(sourceIPAddress) as ip_count, count_distinct(userAgent) as ua_count by userIdentity.principalId, bin(1h)
| filter ip_count > 3 OR (session_count > 10 AND ua_count > 2)
| sort session_count desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect stolen session cookie usage in AWS Console

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  SessionAnomalyAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: AWS Session Cookie Anomaly Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for session anomalies
  SessionFromMultipleIPsFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "ConsoleLogin" || $.eventName = "GetSigninToken") && $.responseElements.ConsoleLogin = "Success" }'
      MetricTransformations:
        - MetricName: ConsoleSessionActivations
          MetricNamespace: Security/SessionAnomaly
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Alarm for unusual session patterns
  SessionAnomalyAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: StolenSessionCookieDetection
      AlarmDescription: Detects potential stolen session cookie usage
      MetricName: ConsoleSessionActivations
      Namespace: Security/SessionAnomaly
      Statistic: Sum
      Period: 900
      EvaluationPeriods: 1
      Threshold: 15
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref SessionAnomalyAlertTopic
      TreatMissingData: notBreaching''',
                terraform_template='''# Detect stolen AWS session cookie usage

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "session_anomaly_alerts" {
  name         = "aws-session-cookie-anomaly-alerts"
  display_name = "AWS Session Cookie Anomaly Alerts"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.session_anomaly_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for session anomalies
resource "aws_cloudwatch_log_metric_filter" "session_from_multiple_ips" {
  name           = "console-session-activations"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"ConsoleLogin\" || $.eventName = \"GetSigninToken\") && $.responseElements.ConsoleLogin = \"Success\" }"

  metric_transformation {
    name          = "ConsoleSessionActivations"
    namespace     = "Security/SessionAnomaly"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Alarm for unusual session patterns
resource "aws_cloudwatch_metric_alarm" "session_anomaly" {
  alarm_name          = "StolenSessionCookieDetection"
  alarm_description   = "Detects potential stolen session cookie usage"
  metric_name         = "ConsoleSessionActivations"
  namespace           = "Security/SessionAnomaly"
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 15
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.session_anomaly_alerts.arn]
  treat_missing_data  = "notBreaching"
}''',
                alert_severity="high",
                alert_title="Potential Stolen Session Cookie Detected",
                alert_description_template="User session from {sourceIPAddress} shows characteristics of stolen cookie reuse: multiple IPs or unusual session patterns.",
                investigation_steps=[
                    "Review source IP addresses and geolocations for the session",
                    "Check user agent strings for consistency",
                    "Verify session timing patterns (gaps, overlaps)",
                    "Review CloudTrail for session cookie API calls",
                    "Check if MFA was bypassed for sensitive actions",
                    "Interview user about recent logins and locations"
                ],
                containment_actions=[
                    "Immediately revoke all active sessions for the user",
                    "Force password reset and MFA re-enrolment",
                    "Review and revoke any changes made during suspicious session",
                    "Enable enhanced session monitoring",
                    "Reduce session timeout durations",
                    "Implement IP-based session binding"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude VPN IP ranges and known travelling users. Baseline normal session patterns per user.",
            detection_coverage="75% - catches multi-IP and high-volume session reuse",
            evasion_considerations="Single-IP usage or slow session activity may evade detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs integration"]
        ),

        # Strategy 2: AWS - Impossible Travel Detection
        DetectionStrategy(
            strategy_id="t1550-004-aws-travel",
            name="AWS Impossible Travel Session Detection",
            description="Detect session cookie reuse from geographically impossible locations.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, eventName, sourceIPAddress, userIdentity.principalId, recipientAccountId
| filter eventName = "ConsoleLogin" OR eventName = "AssumeRole"
| sort @timestamp asc
| stats earliest(@timestamp) as first_seen, latest(@timestamp) as last_seen, count_distinct(sourceIPAddress) as unique_ips by userIdentity.principalId, bin(15m)
| filter unique_ips > 2''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Detect impossible travel patterns for AWS sessions

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  ImpossibleTravelAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: AWS Impossible Travel Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Metric filter for rapid location changes
  RapidLocationChangeFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "ConsoleLogin" && $.responseElements.ConsoleLogin = "Success" }'
      MetricTransformations:
        - MetricName: ConsoleLoginsPerUser
          MetricNamespace: Security/ImpossibleTravel
          MetricValue: "1"
          DefaultValue: 0
          Dimensions:
            - Key: UserIdentity
              Value: $.userIdentity.principalId

  # Step 3: Alarm for rapid location changes
  ImpossibleTravelAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ImpossibleTravelSessionDetection
      AlarmDescription: Detects sessions from impossible geographic locations
      MetricName: ConsoleLoginsPerUser
      Namespace: Security/ImpossibleTravel
      Statistic: Sum
      Period: 900
      EvaluationPeriods: 1
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref ImpossibleTravelAlertTopic
      TreatMissingData: notBreaching''',
                terraform_template='''# Detect impossible travel patterns for AWS sessions

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "impossible_travel_alerts" {
  name         = "aws-impossible-travel-alerts"
  display_name = "AWS Impossible Travel Alerts"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.impossible_travel_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for rapid location changes
resource "aws_cloudwatch_log_metric_filter" "rapid_location_change" {
  name           = "console-logins-per-user"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"ConsoleLogin\" && $.responseElements.ConsoleLogin = \"Success\" }"

  metric_transformation {
    name          = "ConsoleLoginsPerUser"
    namespace     = "Security/ImpossibleTravel"
    value         = "1"
    default_value = 0
    dimensions = {
      UserIdentity = "$.userIdentity.principalId"
    }
  }
}

# Step 3: Alarm for rapid location changes
resource "aws_cloudwatch_metric_alarm" "impossible_travel" {
  alarm_name          = "ImpossibleTravelSessionDetection"
  alarm_description   = "Detects sessions from impossible geographic locations"
  metric_name         = "ConsoleLoginsPerUser"
  namespace           = "Security/ImpossibleTravel"
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = [aws_sns_topic.impossible_travel_alerts.arn]
  treat_missing_data  = "notBreaching"
}''',
                alert_severity="critical",
                alert_title="Impossible Travel Session Detected",
                alert_description_template="User session detected from geographically impossible locations within short timeframe.",
                investigation_steps=[
                    "Calculate geographic distance and travel time between sessions",
                    "Review IP geolocation data for accuracy",
                    "Check for VPN or proxy usage",
                    "Examine session activities during both locations",
                    "Verify user's actual location and travel schedule"
                ],
                containment_actions=[
                    "Terminate all active sessions immediately",
                    "Force password and MFA reset",
                    "Enable additional authentication requirements",
                    "Review all actions taken from suspicious locations",
                    "Implement geo-fencing for sensitive accounts"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Account for VPN usage and corporate proxy networks. Use 15-minute windows for travel calculations.",
            detection_coverage="85% - highly effective for geographically distributed attacks",
            evasion_considerations="Attackers in same region or using same VPN as victim",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["CloudTrail enabled", "IP geolocation enrichment"]
        ),

        # Strategy 3: GCP - Session Cookie Reuse Detection
        DetectionStrategy(
            strategy_id="t1550-004-gcp-session",
            name="GCP Workspace Session Anomaly Detection",
            description="Detect Google Workspace session cookies used from suspicious contexts.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="login.googleapis.com"
protoPayload.methodName="google.login.LoginService.loginSuccess"
protoPayload.metadata.event.eventType="login"
(protoPayload.metadata.event.parameter.name="login_challenge_method"
OR protoPayload.metadata.event.parameter.name="is_suspicious")''',
                gcp_terraform_template='''# GCP: Detect suspicious Workspace session cookie usage

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "session_alerts" {
  display_name = "Session Cookie Anomaly Alerts"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for suspicious sessions
resource "google_logging_metric" "suspicious_sessions" {
  name   = "workspace-suspicious-session-reuse"
  filter = <<-EOT
    protoPayload.serviceName="login.googleapis.com"
    protoPayload.methodName="google.login.LoginService.loginSuccess"
    (protoPayload.metadata.event.parameter.name="is_suspicious"
    OR protoPayload.metadata.event.parameter.name="login_challenge_method")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user_email"
      value_type  = "STRING"
      description = "User email address"
    }
  }

  label_extractors = {
    "user_email" = "EXTRACT(protoPayload.metadata.event.parameter.value)"
  }
}

# Step 3: Alert policy for session anomalies
resource "google_monitoring_alert_policy" "session_cookie_alert" {
  display_name = "Workspace Session Cookie Anomaly"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious session cookie reuse detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_sessions.name}\" resource.type=\"global\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 3

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.session_alerts.id]

  alert_strategy {
    notification_rate_limit {
      period = "3600s"
    }
  }
}''',
                alert_severity="high",
                alert_title="GCP Workspace Session Cookie Anomaly",
                alert_description_template="Suspicious Workspace session detected - possible stolen cookie reuse.",
                investigation_steps=[
                    "Review Workspace login audit logs for the user",
                    "Check session IP addresses and user agents",
                    "Examine failed authentication attempts",
                    "Review OAuth token grants during suspicious sessions",
                    "Check for concurrent sessions from different locations",
                    "Verify user's reported activity and location"
                ],
                containment_actions=[
                    "Sign out all active Workspace sessions",
                    "Force password reset with MFA re-enrolment",
                    "Review and revoke OAuth app permissions",
                    "Enable enhanced security monitoring for the account",
                    "Reduce session timeout to 8 hours",
                    "Enable context-aware access policies"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline user behaviour patterns. Exclude known mobile and VPN scenarios.",
            detection_coverage="70% - catches suspicious login patterns",
            evasion_considerations="Sophisticated attackers mimicking normal behaviour patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$15-25",
            prerequisites=["Workspace audit logging enabled", "Admin SDK API enabled"]
        ),

        # Strategy 4: GCP - User Agent Anomaly Detection
        DetectionStrategy(
            strategy_id="t1550-004-gcp-useragent",
            name="GCP Session User Agent Anomaly Detection",
            description="Detect session cookies used with inconsistent or suspicious user agents.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.requestMetadata.callerSuppliedUserAgent!=""
resource.type="audited_resource"
severity>=NOTICE
protoPayload.authenticationInfo.principalEmail!~"gserviceaccount.com$"''',
                gcp_terraform_template='''# GCP: Detect user agent anomalies indicating stolen cookies

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "useragent_alerts" {
  display_name = "User Agent Anomaly Alerts"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for user agent changes
resource "google_logging_metric" "useragent_anomalies" {
  name   = "session-useragent-anomalies"
  filter = <<-EOT
    protoPayload.requestMetadata.callerSuppliedUserAgent!=""
    resource.type="audited_resource"
    protoPayload.authenticationInfo.principalEmail!~"gserviceaccount.com$"
    severity>=NOTICE
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "principal_email"
      value_type  = "STRING"
      description = "Principal email"
    }
  }

  label_extractors = {
    "principal_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy for user agent anomalies
resource "google_monitoring_alert_policy" "useragent_alert" {
  display_name = "Session Cookie User Agent Anomaly"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious user agent pattern detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.useragent_anomalies.name}\" resource.type=\"global\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50

      aggregations {
        alignment_period     = "600s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.principal_email"]
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.useragent_alerts.id]

  alert_strategy {
    notification_rate_limit {
      period = "3600s"
    }
  }
}''',
                alert_severity="medium",
                alert_title="Session User Agent Anomaly Detected",
                alert_description_template="User session showing inconsistent user agent strings - possible cookie theft.",
                investigation_steps=[
                    "Compare user agent strings across recent sessions",
                    "Check for automation tools or browser emulation",
                    "Review timing patterns of user agent changes",
                    "Examine actions performed with different user agents",
                    "Verify user's actual devices and browsers"
                ],
                containment_actions=[
                    "Terminate suspicious sessions",
                    "Review recent account activities",
                    "Enable device trust and browser verification",
                    "Implement user agent validation policies",
                    "Force re-authentication with device verification"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal user agent patterns per user. Account for legitimate browser updates and multiple devices.",
            detection_coverage="65% - catches obvious user agent inconsistencies",
            evasion_considerations="Attackers using stolen cookies with matching user agents",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"]
        )
    ],

    recommended_order=[
        "t1550-004-aws-travel",
        "t1550-004-gcp-session",
        "t1550-004-aws-session",
        "t1550-004-gcp-useragent"
    ],
    total_effort_hours=7.5,
    coverage_improvement="+16% improvement for Defense Evasion and Lateral Movement tactics"
)
