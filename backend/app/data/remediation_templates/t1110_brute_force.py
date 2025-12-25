"""
T1110 - Brute Force

Adversaries may use brute force techniques to gain access to accounts
when passwords are unknown or when password hashes are obtained.
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
    technique_id="T1110",
    technique_name="Brute Force",
    tactic_ids=["TA0006"],
    mitre_url="https://attack.mitre.org/techniques/T1110/",
    threat_context=ThreatContext(
        description=(
            "Adversaries may use brute force techniques to gain access to accounts "
            "when passwords are unknown or when password hashes are obtained. "
            "This includes password guessing, password spraying, and credential stuffing."
        ),
        attacker_goal="Gain valid credentials through systematic password attempts",
        why_technique=[
            "No prior access needed - can be done externally",
            "Automated tools make large-scale attempts feasible",
            "Weak password policies make success likely",
            "Password reuse across services increases success rate",
            "Cloud services often lack account lockout by default",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=7,
        severity_reasoning=(
            "Brute force attacks are noisy but effective against weak passwords. "
            "Cloud services are particularly vulnerable due to internet exposure. "
            "Success leads directly to valid credential access."
        ),
        business_impact=[
            "Account compromise and data access",
            "Account lockouts causing business disruption",
            "Reputational damage if breach is publicised",
            "Compliance violations for inadequate access controls",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078", "T1087", "T1069"],
        often_follows=["T1589", "T1590"],
    ),
    detection_strategies=[
        # Strategy 1: GuardDuty
        DetectionStrategy(
            strategy_id="t1110-guardduty",
            name="Enable GuardDuty Brute Force Detection",
            description=(
                "AWS GuardDuty detects brute force attempts against EC2 instances "
                "and unusual login patterns that may indicate password attacks."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:EC2/SSHBruteForce",
                    "UnauthorizedAccess:EC2/RDPBruteForce",
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                    "InitialAccess:IAMUser/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty + email alerts for brute force attacks

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty (detects SSH/RDP brute force automatically)
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

  # Step 3: Route brute force findings to email
  BruteForceFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "UnauthorizedAccess:EC2/SSHBruteForce"
            - prefix: "UnauthorizedAccess:EC2/RDPBruteForce"
            - prefix: "CredentialAccess:IAMUser"
      Targets:
        - Id: Email
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
                terraform_template="""# GuardDuty + email alerts for brute force attacks

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty (detects SSH/RDP brute force automatically)
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "guardduty-bruteforce-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route brute force findings to email
resource "aws_cloudwatch_event_rule" "brute_force" {
  name = "guardduty-bruteforce-alerts"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:EC2/SSHBruteForce" },
        { prefix = "UnauthorizedAccess:EC2/RDPBruteForce" },
        { prefix = "CredentialAccess:IAMUser" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.brute_force.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
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
                alert_severity="high",
                alert_title="GuardDuty: Brute Force Attack Detected",
                alert_description_template=(
                    "GuardDuty detected brute force activity: {finding_type}. "
                    "Target: {target}. Source IP: {source_ip}. "
                    "Immediate investigation recommended."
                ),
                investigation_steps=[
                    "Identify the target resource (EC2, IAM user)",
                    "Check if the source IP is known malicious",
                    "Review authentication logs for the target",
                    "Determine if any attempts were successful",
                    "Check for post-compromise activity if successful",
                ],
                containment_actions=[
                    "Block source IP at security group or WAF level",
                    "Enable MFA on targeted accounts",
                    "Reset passwords for potentially compromised accounts",
                    "Review and strengthen password policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known vulnerability scanners and penetration testing IPs",
            detection_coverage="70% - catches network-based brute force",
            evasion_considerations="Distributed attacks from multiple IPs, slow attacks",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events",
            prerequisites=["AWS account with appropriate IAM permissions"],
        ),
        # Strategy 2: Failed Login Monitoring
        DetectionStrategy(
            strategy_id="t1110-failed-logins",
            name="Failed Console Login Monitoring",
            description=(
                "Monitor CloudTrail for repeated failed console login attempts "
                "which indicate password guessing or spraying attacks."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.userName as user, sourceIPAddress,
       responseElements.ConsoleLogin as result, errorMessage
| filter eventName = "ConsoleLogin"
| stats count(*) as total_attempts,
        sum(case when result = "Failure" then 1 else 0 end) as failed_attempts,
        count_distinct(sourceIPAddress) as unique_ips
  by user, bin(15m) as time_window
| filter failed_attempts >= 5
| sort time_window desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Alert on 5+ failed console logins in 5 minutes

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

  # Step 2: Count failed logins
  FailedLoginFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "ConsoleLogin" && $.responseElements.ConsoleLogin = "Failure" }'
      MetricTransformations:
        - MetricName: FailedLogins
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alert when threshold exceeded
  FailedLoginAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: BruteForce-FailedLogins
      MetricName: FailedLogins
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 5
      ComparisonOperator: GreaterThanOrEqualToThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Alert on 5+ failed console logins in 5 minutes

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create alert topic
resource "aws_sns_topic" "alerts" {
  name = "failed-login-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Count failed logins
resource "aws_cloudwatch_log_metric_filter" "failed_logins" {
  name           = "failed-console-logins"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"ConsoleLogin\" && $.responseElements.ConsoleLogin = \"Failure\" }"

  metric_transformation {
    name      = "FailedLogins"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alert when threshold exceeded
resource "aws_cloudwatch_metric_alarm" "failed_logins" {
  alarm_name          = "BruteForce-FailedLogins"
  metric_name         = "FailedLogins"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="Excessive Failed Login Attempts",
                alert_description_template=(
                    "User {user} had {failed_attempts} failed login attempts in 15 minutes "
                    "from {unique_ips} unique IP addresses. This may indicate a brute force attack."
                ),
                investigation_steps=[
                    "Identify all source IPs attempting to authenticate",
                    "Check if any attempts were successful after failures",
                    "Determine if targeted user account is valid",
                    "Review timing and pattern of attempts",
                    "Check threat intelligence for source IPs",
                ],
                containment_actions=[
                    "Temporarily lock the targeted account",
                    "Block source IPs at network level",
                    "Force password reset for targeted accounts",
                    "Enable MFA if not already required",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Adjust threshold based on normal failed login baseline; exclude service accounts",
            detection_coverage="80% - catches console-based attacks",
            evasion_considerations="Password spraying (few attempts per account), API-based attacks",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-15",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
        # Strategy 3: Password Spray Detection
        DetectionStrategy(
            strategy_id="t1110-password-spray",
            name="Password Spray Attack Detection",
            description=(
                "Detect password spraying by identifying a single IP attempting "
                "to authenticate against multiple accounts in a short time window."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.userName as user, sourceIPAddress,
       responseElements.ConsoleLogin as result
| filter eventName = "ConsoleLogin"
| stats count_distinct(user) as targeted_users,
        count(*) as total_attempts,
        sum(case when result = "Failure" then 1 else 0 end) as failures
  by sourceIPAddress, bin(30m) as time_window
| filter targeted_users >= 3 and failures >= 3
| sort time_window desc""",
                alert_severity="critical",
                alert_title="Password Spray Attack Detected",
                alert_description_template=(
                    "IP {sourceIPAddress} attempted to authenticate against {targeted_users} "
                    "different user accounts in 30 minutes with {failures} failures. "
                    "This is a strong indicator of password spraying."
                ),
                investigation_steps=[
                    "Identify all user accounts targeted by the source IP",
                    "Check if any authentications were successful",
                    "Gather threat intelligence on the source IP",
                    "Review if targeted accounts follow a pattern (e.g., executives)",
                    "Check for similar activity from related IP ranges",
                ],
                containment_actions=[
                    "Block the source IP immediately",
                    "Force password reset for all targeted accounts",
                    "Enable MFA on all targeted accounts",
                    "Notify affected users of potential compromise attempt",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Exclude known SSO/federation services; adjust user threshold",
            detection_coverage="90% - highly effective for spray attacks",
            evasion_considerations="Distributed spraying from multiple IPs, very slow attacks",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
        # Strategy 4: API-Based Brute Force
        DetectionStrategy(
            strategy_id="t1110-api-brute-force",
            name="API Authentication Failure Monitoring",
            description=(
                "Monitor for repeated API authentication failures which may indicate "
                "programmatic brute force attacks against access keys or tokens."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.accessKeyId as accessKey,
       sourceIPAddress, eventName, errorCode, errorMessage
| filter errorCode in ["AccessDenied", "UnauthorizedAccess", "InvalidClientTokenId",
    "SignatureDoesNotMatch", "IncompleteSignature"]
| stats count(*) as error_count, count_distinct(eventName) as unique_apis
  by sourceIPAddress, bin(15m) as time_window
| filter error_count >= 10
| sort time_window desc""",
                alert_severity="high",
                alert_title="API Authentication Brute Force Detected",
                alert_description_template=(
                    "IP {sourceIPAddress} generated {error_count} authentication errors "
                    "across {unique_apis} APIs in 15 minutes. This may indicate API key brute forcing."
                ),
                investigation_steps=[
                    "Identify which APIs were targeted",
                    "Check if any valid access keys were exposed",
                    "Review recent code deployments for credential leaks",
                    "Search for the source IP in threat intelligence",
                    "Check for any successful API calls from the same IP",
                ],
                containment_actions=[
                    "Block the source IP at WAF/security group",
                    "Rotate any potentially exposed access keys",
                    "Review IAM access key inventory",
                    "Enable CloudTrail insights for anomaly detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known development/test environments; tune threshold for your baseline",
            detection_coverage="60% - catches programmatic attacks",
            evasion_considerations="Using valid credentials obtained elsewhere, slow enumeration",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "All API events logged"],
        ),
        # Strategy 5: GCP Failed Login Detection
        DetectionStrategy(
            strategy_id="t1110-gcp-failed-logins",
            name="GCP Failed Authentication Detection",
            description=(
                "Detect brute force and credential stuffing attacks against GCP resources "
                "by monitoring failed login attempts, failed API authentication, and "
                "SSH brute force against Compute Engine VMs via Cloud Logging."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""-- GCP Brute Force Detection Query
-- Detects multiple failed authentication attempts
protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
AND (
  -- Failed API authentication
  protoPayload.status.code!=0
  OR protoPayload.authorizationInfo.granted=false
  -- SSH brute force (via serial console logs)
  OR jsonPayload.message=~"Failed password"
  OR jsonPayload.message=~"authentication failure"
)""",
                gcp_terraform_template="""# GCP: Brute Force Detection for T1110
# Monitors failed authentication attempts across GCP services

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  project      = var.project_id
  display_name = "Security Alerts - Brute Force"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for failed authentications
resource "google_logging_metric" "failed_auth" {
  project     = var.project_id
  name        = "brute-force-failed-auth"
  description = "Count of failed authentication attempts"
  filter      = <<-EOT
    protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
    AND (protoPayload.status.code!=0 OR protoPayload.authorizationInfo.granted=false)
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal attempting authentication"
    }
  }

  label_extractors = {
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy for brute force threshold
resource "google_monitoring_alert_policy" "brute_force" {
  project      = var.project_id
  display_name = "T1110 - Brute Force Detected"
  combiner     = "OR"
  enabled      = true

  conditions {
    display_name = "High Failed Auth Rate"
    condition_threshold {
      filter          = "metric.type=\\"logging.googleapis.com/user/brute-force-failed-auth\\""
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      duration        = "300s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
        group_by_fields    = ["metric.label.principal"]
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.name]

  documentation {
    content   = "Potential brute force attack detected. Multiple failed authentication attempts from the same principal."
    mime_type = "text/markdown"
  }
}

# Step 4: Log-based metric for SSH brute force
resource "google_logging_metric" "ssh_brute_force" {
  project     = var.project_id
  name        = "brute-force-ssh-failed"
  description = "Count of failed SSH login attempts"
  filter      = <<-EOT
    resource.type="gce_instance"
    AND (jsonPayload.message=~"Failed password" OR jsonPayload.message=~"authentication failure")
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "instance_id"
      value_type  = "STRING"
      description = "Compute Engine instance ID"
    }
  }

  label_extractors = {
    "instance_id" = "EXTRACT(resource.labels.instance_id)"
  }
}

# Step 5: Alert for SSH brute force
resource "google_monitoring_alert_policy" "ssh_brute_force" {
  project      = var.project_id
  display_name = "T1110 - SSH Brute Force Detected"
  combiner     = "OR"
  enabled      = true

  conditions {
    display_name = "High SSH Failed Login Rate"
    condition_threshold {
      filter          = "metric.type=\\"logging.googleapis.com/user/brute-force-ssh-failed\\""
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      duration        = "300s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
        group_by_fields    = ["metric.label.instance_id"]
      }

      trigger {
        count = 1
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.name]

  documentation {
    content   = "SSH brute force attack detected against Compute Engine instance."
    mime_type = "text/markdown"
  }
}""",
                alert_severity="high",
                alert_title="GCP: Brute Force Attack Detected",
                alert_description_template=(
                    "Multiple failed authentication attempts detected from {principal}. "
                    "This may indicate a brute force or credential stuffing attack against GCP resources."
                ),
                investigation_steps=[
                    "Identify the source IP addresses of failed attempts",
                    "Check if the targeted principal exists and is active",
                    "Review Cloud Audit Logs for successful authentications from same IPs",
                    "Check if any successful access occurred after failed attempts",
                    "Correlate with organisation login events in Admin Console",
                    "Review Security Command Centre for related findings",
                ],
                containment_actions=[
                    "Block source IPs in Cloud Armour or VPC firewall",
                    "Enable 2-Step Verification for targeted accounts",
                    "Reset credentials for any potentially compromised accounts",
                    "Review and revoke suspicious OAuth tokens",
                    "Enable Context-Aware Access for additional protection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude known CI/CD service accounts; adjust threshold based on normal login patterns",
            detection_coverage="60% - detects most brute force patterns",
            evasion_considerations="Slow attacks below threshold, distributed attacks across IPs",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$5-15 (Cloud Monitoring alerts)",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Cloud Logging API enabled",
                "Cloud Monitoring API enabled",
            ],
        ),
    ],
    recommended_order=[
        "t1110-guardduty",
        "t1110-failed-logins",
        "t1110-password-spray",
        "t1110-api-brute-force",
        "t1110-gcp-failed-logins",
    ],
    total_effort_hours=8.0,
    coverage_improvement="+30% improvement for Credential Access tactic",
)
