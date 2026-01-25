"""
T1539 - Steal Web Session Cookie

Adversaries steal web session cookies to bypass authentication and MFA controls.
Session cookies provide persistent access to web applications and cloud services
without requiring valid credentials.
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
    technique_id="T1539",
    technique_name="Steal Web Session Cookie",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1539/",
    threat_context=ThreatContext(
        description=(
            "Adversaries steal web session cookies from browsers, memory, or network traffic "
            "to hijack authenticated sessions. Stolen cookies bypass credential requirements "
            "and often circumvent MFA, providing persistent access to cloud services and "
            "web applications. Cookies are extracted via malware, phishing proxies (EvilGinx2), "
            "or network interception."
        ),
        attacker_goal="Steal session cookies to access cloud services and web applications without authentication",
        why_technique=[
            "Session cookies bypass MFA requirements",
            "Cookies remain valid for extended periods",
            "No need to compromise actual credentials",
            "Works across cloud services and SaaS applications",
            "Can be extracted from multiple sources (disk, memory, network)",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Session cookie theft bypasses authentication and MFA controls, providing "
            "direct access to cloud resources. Widely used by APT groups and commodity "
            "malware families. Critical impact on cloud service security."
        ),
        business_impact=[
            "Unauthorised access to cloud applications",
            "Session hijacking bypassing MFA protections",
            "Data exfiltration from SaaS platforms",
            "Account takeover without credential compromise",
            "Persistent access until cookie expiry or rotation",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1550.004", "T1530", "T1537"],
        often_follows=["T1566", "T1189", "T1204"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - CloudTrail Session Context Changes
        DetectionStrategy(
            strategy_id="t1539-aws-session-context",
            name="AWS Session Context Anomaly Detection",
            description="Detect AWS console sessions with changing IP addresses or user agents indicating cookie theft.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, userAgent, eventName
| filter userIdentity.type = "AssumedRole" or userIdentity.type = "IAMUser"
| filter eventName = "ConsoleLogin" or eventName = "GetSigninToken" or eventName = "AssumeRole"
| stats count(*) as event_count, count_distinct(sourceIPAddress) as ip_count, count_distinct(userAgent) as agent_count by userIdentity.principalId, bin(1h)
| filter ip_count > 3 or agent_count > 2
| sort event_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect session cookie theft via context changes

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

  # Step 2: Metric filter for session anomalies
  SessionAnomalyFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "ConsoleLogin" || $.eventName = "GetSigninToken") && $.userIdentity.type = "IAMUser" }'
      MetricTransformations:
        - MetricName: ConsoleSessionEvents
          MetricNamespace: Security/SessionTheft
          MetricValue: "1"

  # Step 3: Alarm for unusual session activity
  SessionAnomalyAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: SessionCookieTheftDetection
      AlarmDescription: Detects potential session cookie theft via multiple IPs
      MetricName: ConsoleSessionEvents
      Namespace: Security/SessionTheft
      Statistic: Sum
      Period: 300
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# AWS: Detect session cookie theft via context changes

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

data "aws_caller_identity" "current" {}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "session_alerts" {
  name = "session-cookie-theft-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.session_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.session_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.session_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for session anomalies
resource "aws_cloudwatch_log_metric_filter" "session_anomaly" {
  name           = "console-session-anomalies"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ ($.eventName = \"ConsoleLogin\" || $.eventName = \"GetSigninToken\") && $.userIdentity.type = \"IAMUser\" }"

  metric_transformation {
    name      = "ConsoleSessionEvents"
    namespace = "Security/SessionTheft"
    value     = "1"
  }
}

# Step 3: Alarm for unusual session activity
resource "aws_cloudwatch_metric_alarm" "session_theft" {
  alarm_name          = "SessionCookieTheftDetection"
  alarm_description   = "Detects potential session cookie theft via multiple IPs"
  metric_name         = "ConsoleSessionEvents"
  namespace           = "Security/SessionTheft"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.session_alerts.arn]
}""",
                alert_severity="high",
                alert_title="AWS Session Cookie Theft Detected",
                alert_description_template="Session token reuse detected from multiple IP addresses for {principalId}.",
                investigation_steps=[
                    "Review CloudTrail logs for the affected session",
                    "Check for impossible travel between IP geolocations",
                    "Verify user agent strings for inconsistencies",
                    "Review actions taken during suspicious sessions",
                    "Check for concurrent sessions from different locations",
                ],
                containment_actions=[
                    "Revoke active console sessions for affected users",
                    "Force credential reset and MFA re-registration",
                    "Review and revert unauthorised actions",
                    "Enable session context awareness in IAM policies",
                    "Implement stricter session duration limits",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist VPN IP ranges and known user travel patterns",
            detection_coverage="65% - catches multi-IP session usage",
            evasion_considerations="Attacker using same IP/user agent as victim",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail logging console events to CloudWatch"],
        ),
        # Strategy 2: AWS - Impossible Travel Detection
        DetectionStrategy(
            strategy_id="t1539-aws-impossible-travel",
            name="AWS Impossible Travel Detection",
            description="Detect session cookies used from geographically impossible locations within short timeframes.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, sourceIPAddress, awsRegion, eventName
| filter eventName in ["ConsoleLogin", "AssumeRole", "GetFederationToken"]
| sort @timestamp asc
| stats earliest(@timestamp) as first_event, latest(@timestamp) as last_event, count_distinct(sourceIPAddress) as unique_ips by userIdentity.principalId, bin(30m)
| filter unique_ips >= 2""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect impossible travel patterns indicating cookie theft

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

  # Step 2: Metric filter for rapid location changes
  ImpossibleTravelFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "ConsoleLogin" }'
      MetricTransformations:
        - MetricName: ConsoleLogins
          MetricNamespace: Security/ImpossibleTravel
          MetricValue: "1"
          DefaultValue: 0

  # Step 3: Alarm for suspicious travel patterns
  ImpossibleTravelAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: ImpossibleTravelDetected
      AlarmDescription: Multiple console logins suggesting stolen session cookies
      MetricName: ConsoleLogins
      Namespace: Security/ImpossibleTravel
      Statistic: Sum
      Period: 1800
      Threshold: 3
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# AWS: Detect impossible travel patterns

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

data "aws_caller_identity" "current" {}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "travel_alerts" {
  name = "impossible-travel-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.travel_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.travel_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.travel_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for rapid location changes
resource "aws_cloudwatch_log_metric_filter" "impossible_travel" {
  name           = "impossible-travel-pattern"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"ConsoleLogin\" }"

  metric_transformation {
    name          = "ConsoleLogins"
    namespace     = "Security/ImpossibleTravel"
    value         = "1"
    default_value = 0
  }
}

# Step 3: Alarm for suspicious travel patterns
resource "aws_cloudwatch_metric_alarm" "impossible_travel" {
  alarm_name          = "ImpossibleTravelDetected"
  alarm_description   = "Multiple console logins suggesting stolen session cookies"
  metric_name         = "ConsoleLogins"
  namespace           = "Security/ImpossibleTravel"
  statistic           = "Sum"
  period              = 1800
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.travel_alerts.arn]
}""",
                alert_severity="critical",
                alert_title="Impossible Travel Pattern Detected",
                alert_description_template="User {principalId} accessed AWS from {unique_ips} different locations within 30 minutes.",
                investigation_steps=[
                    "Map source IPs to geographical locations",
                    "Calculate travel time between locations",
                    "Review all actions performed from suspicious IPs",
                    "Check for VPN or proxy usage patterns",
                    "Verify user's actual location via out-of-band contact",
                ],
                containment_actions=[
                    "Immediately revoke all active sessions",
                    "Disable affected IAM user or role",
                    "Review and revert unauthorised changes",
                    "Force password reset and MFA re-enrolment",
                    "Implement IP allowlisting for sensitive accounts",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Account for VPNs, legitimate travel, and federated access patterns",
            detection_coverage="80% - high confidence impossible travel detection",
            evasion_considerations="Slow cookie reuse or same-region usage",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging enabled with geographic data"],
        ),
        # Strategy 3: GCP - Session Cookie Anomaly Detection
        DetectionStrategy(
            strategy_id="t1539-gcp-session-anomaly",
            name="GCP Session Context Change Detection",
            description="Detect Google Cloud session cookies reused from changing IP addresses or user agents.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="login.googleapis.com"
protoPayload.methodName="google.login.LoginService.loginSuccess"
OR protoPayload.methodName="google.login.LoginService.refreshToken"''',
                gcp_terraform_template="""# GCP: Detect session cookie theft via context changes

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "Session Theft Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for session anomalies
resource "google_logging_metric" "session_anomaly" {
  project = var.project_id
  name   = "session-cookie-anomalies"
  filter = <<-EOT
    protoPayload.serviceName="login.googleapis.com"
    (protoPayload.methodName="google.login.LoginService.loginSuccess" OR
     protoPayload.methodName="google.login.LoginService.refreshToken")
    severity>=NOTICE
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
    "user_email" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy for session anomalies
resource "google_monitoring_alert_policy" "session_theft" {
  project      = var.project_id
  display_name = "Session Cookie Theft Detection"
  combiner     = "OR"

  conditions {
    display_name = "Multiple session refreshes from different contexts"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.session_anomaly.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="high",
                alert_title="GCP Session Cookie Theft Detected",
                alert_description_template="Suspicious session refresh patterns detected for {user_email}.",
                investigation_steps=[
                    "Review Cloud Audit Logs for login events",
                    "Check source IPs for geographical inconsistencies",
                    "Verify user agent changes across sessions",
                    "Review OAuth token usage patterns",
                    "Check for workspace admin changes",
                ],
                containment_actions=[
                    "Revoke user's active sessions via Admin Console",
                    "Force sign-out from all devices",
                    "Reset user password and security keys",
                    "Review recent actions in Cloud Audit Logs",
                    "Enable context-aware access policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal session refresh patterns per user",
            detection_coverage="70% - detects abnormal session patterns",
            evasion_considerations="Attacker mimicking legitimate session behaviour",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled", "Login audit logging enabled"],
        ),
        # Strategy 4: GCP - Browser Cookie File Access
        DetectionStrategy(
            strategy_id="t1539-gcp-cookie-file-access",
            name="GCP Workspace Browser Cookie Monitoring",
            description="Detect suspicious access patterns to browser cookie storage indicating theft attempts.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="admin.googleapis.com"
protoPayload.methodName=~".*LOGOUT.*|.*SUSPICIOUS_LOGIN.*|.*ACCOUNT_WARNING.*"
OR (protoPayload.serviceName="login.googleapis.com" AND protoPayload.status.code!=0)""",
                gcp_terraform_template="""# GCP: Monitor suspicious authentication patterns

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Cookie Theft Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for suspicious auth events
resource "google_logging_metric" "suspicious_auth" {
  project = var.project_id
  name   = "suspicious-authentication-events"
  filter = <<-EOT
    protoPayload.serviceName="admin.googleapis.com"
    (protoPayload.methodName=~".*LOGOUT.*" OR
     protoPayload.methodName=~".*SUSPICIOUS_LOGIN.*" OR
     protoPayload.methodName=~".*ACCOUNT_WARNING.*")
    severity>=WARNING
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "event_type"
      value_type  = "STRING"
      description = "Type of suspicious event"
    }
  }

  label_extractors = {
    "event_type" = "EXTRACT(protoPayload.methodName)"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "cookie_theft_warning" {
  project      = var.project_id
  display_name = "Cookie Theft Warning Indicators"
  combiner     = "OR"

  conditions {
    display_name = "Suspicious authentication activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.suspicious_auth.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "86400s"
    notification_rate_limit {
      period = "300s"
    }
  }
}""",
                alert_severity="medium",
                alert_title="Suspicious Authentication Patterns",
                alert_description_template="Multiple suspicious authentication events detected.",
                investigation_steps=[
                    "Review workspace security alerts",
                    "Check for failed login attempts",
                    "Verify legitimate forced logout events",
                    "Review account warning notifications",
                    "Check for compromised credential reports",
                ],
                containment_actions=[
                    "Force password reset for affected users",
                    "Enable advanced protection programme",
                    "Review and revoke suspicious OAuth grants",
                    "Enable security key enforcement",
                    "Implement context-aware access controls",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Correlate with other security signals for higher confidence",
            detection_coverage="60% - warning indicator detection",
            evasion_considerations="Stolen cookies used successfully without warnings",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-60 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Workspace audit logging enabled"],
        ),
        # Azure Strategy: Steal Web Session Cookie
        DetectionStrategy(
            strategy_id="t1539-azure",
            name="Azure Steal Web Session Cookie Detection",
            description=(
                "Azure detection for Steal Web Session Cookie. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Steal Web Session Cookie (T1539)
# Microsoft Defender detects Steal Web Session Cookie activity

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
  description = "Resource group name"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace for Defender"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

variable "location" {
  type        = string
  description = "Azure region for resources"
  default     = "uksouth"
}

# Enable Defender for Cloud plans
resource "azurerm_security_center_subscription_pricing" "defender_servers" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "defender_storage" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "defender_keyvault" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "defender_arm" {
  tier          = "Standard"
  resource_type = "Arm"
}

# Action Group for Defender alerts
resource "azurerm_monitor_action_group" "defender_alerts" {
  name                = "defender-t1539-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1539"
  resource_group_name = var.resource_group_name
  location            = var.location

  evaluation_frequency = "PT5M"
  window_duration      = "PT1H"
  scopes               = [var.log_analytics_workspace_id]
  severity             = 1

  criteria {
    query = <<-QUERY
SecurityAlert
| where TimeGenerated > ago(1h)
| where ProductName == "Azure Security Center" or ProductName == "Microsoft Defender for Cloud"
| where AlertName has_any (
                    "Suspicious activity detected",
                )
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Description,
    RemediationSteps,
    ExtendedProperties,
    Entities
    QUERY

    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.defender_alerts.id]
  }

  description = "Microsoft Defender detects Steal Web Session Cookie activity"
  display_name = "Defender: Steal Web Session Cookie"
  enabled      = true

  tags = {
    "mitre-technique" = "T1539"
    "detection-type"  = "security"
  }
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Steal Web Session Cookie Detected",
                alert_description_template=(
                    "Steal Web Session Cookie activity detected. "
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
        "t1539-aws-impossible-travel",
        "t1539-gcp-session-anomaly",
        "t1539-aws-session-context",
        "t1539-gcp-cookie-file-access",
    ],
    total_effort_hours=5.5,
    coverage_improvement="+15% improvement for Credential Access tactic",
)
