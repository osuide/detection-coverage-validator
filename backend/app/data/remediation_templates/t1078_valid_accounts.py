"""
T1078 - Valid Accounts

Adversaries may obtain and abuse credentials of existing accounts as a means
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
    technique_id="T1078",
    technique_name="Valid Accounts",
    tactic_ids=["TA0001", "TA0003", "TA0004", "TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1078/",

    threat_context=ThreatContext(
        description=(
            "Adversaries obtain and abuse legitimate credentials to gain access to systems and networks. "
            "This technique enables initial access, persistence, privilege escalation, and defence evasion. "
            "Compromised credentials bypass access controls and may grant increased privileges or access to "
            "restricted network areas. Attackers sometimes exploit inactive accounts belonging to former "
            "employees to evade detection."
        ),
        attacker_goal="Gain and maintain access using legitimate credentials without deploying malware",
        why_technique=[
            "Legitimate credentials bypass perimeter security controls",
            "Activity blends with normal user behaviour, evading detection",
            "No malware signatures to detect",
            "Access persists until password rotation or credential revocation",
            "Can enable privilege escalation with high-permission accounts",
            "Inactive accounts provide covert access channels"
        ],
        known_threat_actors=[
            "APT28 (Fancy Bear)",
            "APT29 (Cozy Bear)",
            "APT33 (Elfin)",
            "APT39",
            "APT41",
            "Lazarus Group",
            "Wizard Spider",
            "FIN4",
            "FIN5",
            "FIN6",
            "FIN7",
            "FIN8",
            "Carbanak",
            "Dragonfly",
            "LAPSUS$",
            "Volt Typhoon",
            "Scattered Spider"
        ],
        recent_campaigns=[
            Campaign(
                name="SolarWinds/SUNBURST",
                year=2020,
                description="APT29 used compromised credentials to access victim cloud environments and establish persistence",
                reference_url="https://www.mandiant.com/resources/sunburst-additional-technical-details"
            ),
            Campaign(
                name="LAPSUS$ Attacks",
                year=2022,
                description="Purchased credentials from initial access brokers to compromise Microsoft, Nvidia, Samsung, and other major organisations",
                reference_url="https://www.microsoft.com/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration/"
            ),
            Campaign(
                name="Scattered Spider MGM Attack",
                year=2023,
                description="Social engineering and SIM swapping to obtain valid credentials for ransomware deployment at MGM Resorts",
                reference_url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"
            ),
            Campaign(
                name="Volt Typhoon Infrastructure Targeting",
                year=2023,
                description="Long-term compromise of critical infrastructure using valid credentials for living-off-the-land persistence",
                reference_url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a"
            )
        ],
        prevalence="very_common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Valid account abuse is the most common initial access vector in cloud breaches and "
            "a critical persistence mechanism. Credential-based access is difficult to detect without "
            "behavioural analysis, providing attackers with long-term access. The technique spans "
            "multiple tactics (Initial Access, Persistence, Privilege Escalation, Defence Evasion), "
            "making it a versatile and high-impact threat."
        ),
        business_impact=[
            "Unauthorised access to sensitive data and systems",
            "Data exfiltration without triggering traditional security controls",
            "Lateral movement to connected systems and accounts",
            "Ransomware and destructive attacks",
            "Regulatory compliance violations (GDPR, HIPAA, PCI-DSS)",
            "Reputational damage from data breaches",
            "Long-term persistent access for espionage"
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1087", "T1069", "T1530", "T1098", "T1136"],
        often_follows=["T1566", "T1110", "T1552", "T1528"]
    ),

    detection_strategies=[
        # Strategy 1: AWS GuardDuty
        DetectionStrategy(
            strategy_id="t1078-aws-guardduty",
            name="AWS GuardDuty Credential Abuse Detection",
            description=(
                "AWS GuardDuty provides managed detection for suspicious credential usage "
                "including impossible travel, unusual API calls, credential exfiltration, "
                "and anomalous authentication patterns."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
                    "InitialAccess:IAMUser/AnomalousBehavior",
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                    "Persistence:IAMUser/AnomalousBehavior"
                ],
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty + email alerts for credential abuse (T1078)

Parameters:
  AlertEmail:
    Type: String
    Description: Email address for security alerts

Resources:
  # Step 1: Enable GuardDuty (detects credential abuse automatically)
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: FIFTEEN_MINUTES

  # Step 2: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty Credential Abuse Alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route credential findings to email
  CredentialFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1078-GuardDutyCredentialAbuse
      Description: Alert on suspicious credential usage
      EventPattern:
        source: [aws.guardduty]
        detail:
          type:
            - prefix: "UnauthorizedAccess:IAMUser"
            - prefix: "InitialAccess:IAMUser"
            - prefix: "CredentialAccess:IAMUser"
            - prefix: "Persistence:IAMUser"
      State: ENABLED
      Targets:
        - Id: EmailAlert
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
            Resource: !Ref AlertTopic''',
                terraform_template='''# AWS GuardDuty + email alerts for credential abuse (T1078)

variable "alert_email" {
  type        = string
  description = "Email address for security alerts"
}

# Step 1: Enable GuardDuty (detects credential abuse automatically)
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "credential_alerts" {
  name         = "guardduty-credential-alerts"
  display_name = "GuardDuty Credential Abuse Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.credential_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route credential findings to email
resource "aws_cloudwatch_event_rule" "credential_findings" {
  name        = "T1078-GuardDutyCredentialAbuse"
  description = "Alert on suspicious credential usage"

  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    detail = {
      type = [
        { prefix = "UnauthorizedAccess:IAMUser" },
        { prefix = "InitialAccess:IAMUser" },
        { prefix = "CredentialAccess:IAMUser" },
        { prefix = "Persistence:IAMUser" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.credential_findings.name
  target_id = "EmailAlert"
  arn       = aws_sns_topic.credential_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.credential_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.credential_alerts.arn
    }]
  })
}''',
                alert_severity="high",
                alert_title="GuardDuty: Suspicious Credential Activity",
                alert_description_template=(
                    "GuardDuty detected suspicious credential usage: {finding_type}. "
                    "User: {principal}. Source IP: {source_ip}. "
                    "This may indicate compromised credentials."
                ),
                investigation_steps=[
                    "Review the GuardDuty finding details in AWS Console",
                    "Check CloudTrail for all API calls from the affected principal in the last 24 hours",
                    "Verify if the source IP is known/expected for this user",
                    "Check geolocation of source IP for impossible travel indicators",
                    "Contact the user to confirm if activity was legitimate",
                    "Review IAM permissions to assess potential blast radius",
                    "Check for new access keys or credential creation by this principal"
                ],
                containment_actions=[
                    "Disable the IAM user's console access and access keys immediately",
                    "Rotate all access keys for the affected user",
                    "Enable MFA if not already enabled",
                    "Review and revoke any active sessions using AWS STS",
                    "Reset the user's password with MFA verification",
                    "Review and revert any unauthorised IAM changes"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Add trusted IPs to GuardDuty IP allow lists; suppress findings for known CI/CD systems and VPN endpoints",
            detection_coverage="65% - covers anomalous behaviour patterns and known malicious activity",
            evasion_considerations="Attackers may use VPNs in same region, mimic normal working hours, or employ slow-and-low techniques",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4-10 per million events analysed",
            prerequisites=["AWS account with appropriate IAM permissions", "CloudTrail enabled"]
        ),

        # Strategy 2: AWS Impossible Travel
        DetectionStrategy(
            strategy_id="t1078-aws-impossible-travel",
            name="Impossible Travel Detection via CloudWatch",
            description=(
                "Detect when the same user authenticates from geographically distant locations "
                "within a timeframe that makes physical travel impossible, indicating credential compromise."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.arn as user, sourceIPAddress, eventName,
       userAgent, awsRegion
| filter eventName = "ConsoleLogin" and responseElements.ConsoleLogin = "Success"
| stats earliest(@timestamp) as first_login,
        latest(@timestamp) as last_login,
        count(*) as login_count,
        count_distinct(sourceIPAddress) as unique_ips,
        values(sourceIPAddress) as ip_addresses
  by user, bin(1h) as hour_window
| filter unique_ips > 1
| sort last_login desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Impossible travel detection for T1078

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: Metric filter for multiple IPs
  MultipleIPMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "ConsoleLogin" && $.responseElements.ConsoleLogin = "Success" }'
      MetricTransformations:
        - MetricName: ConsoleLoginFromMultipleIPs
          MetricNamespace: Security/T1078
          MetricValue: "1"
          DefaultValue: 0

  # Step 2: Create alarm for impossible travel
  ImpossibleTravelAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1078-ImpossibleTravel
      AlarmDescription: Multiple console logins from different IPs detected
      MetricName: ConsoleLoginFromMultipleIPs
      Namespace: Security/T1078
      Statistic: Sum
      Period: 3600
      EvaluationPeriods: 1
      Threshold: 2
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn
      TreatMissingData: notBreaching''',
                terraform_template='''# AWS Impossible travel detection for T1078

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "sns_topic_arn" {
  type        = string
  description = "SNS topic ARN for alerts"
}

# Step 1: Metric filter for multiple IPs
resource "aws_cloudwatch_log_metric_filter" "multiple_ips" {
  name           = "console-login-multiple-ips"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"ConsoleLogin\" && $.responseElements.ConsoleLogin = \"Success\" }"

  metric_transformation {
    name          = "ConsoleLoginFromMultipleIPs"
    namespace     = "Security/T1078"
    value         = "1"
    default_value = 0
  }
}

# Step 2: Create alarm for impossible travel
resource "aws_cloudwatch_metric_alarm" "impossible_travel" {
  alarm_name          = "T1078-ImpossibleTravel"
  alarm_description   = "Multiple console logins from different IPs detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ConsoleLoginFromMultipleIPs"
  namespace           = "Security/T1078"
  period              = 3600
  statistic           = "Sum"
  threshold           = 2
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"
}''',
                alert_severity="high",
                alert_title="Impossible Travel: Multiple Login Locations",
                alert_description_template=(
                    "User {user} logged in from {unique_ips} different IP addresses within 1 hour. "
                    "IP addresses: {ip_addresses}. This may indicate credential compromise."
                ),
                investigation_steps=[
                    "Identify all IP addresses used by the user in the detection window",
                    "Geolocate the IPs to determine physical distance and travel time required",
                    "Check if any IPs are known VPN endpoints or corporate egress points",
                    "Review all API calls made from each IP address during the session",
                    "Check user agent strings for consistency",
                    "Contact the user via out-of-band communication to verify login locations",
                    "Review recent password changes or MFA modifications"
                ],
                containment_actions=[
                    "Force logout all active sessions for the user immediately",
                    "Temporarily disable console access",
                    "Invalidate all access keys",
                    "Require password reset with MFA verification",
                    "Review and revert any changes made during suspicious sessions"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known VPN exit nodes, corporate proxies, and cloud shell IPs; adjust time window based on organisation",
            detection_coverage="45% - catches obvious geographic anomalies but misses same-region attacks",
            evasion_considerations="Attackers may use VPNs in expected geographic locations or time activity to match work patterns",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-20 depending on log volume",
            prerequisites=["CloudTrail enabled", "CloudTrail logs sent to CloudWatch Logs"]
        ),

        # Strategy 3: AWS Off-Hours Access
        DetectionStrategy(
            strategy_id="t1078-aws-off-hours",
            name="Off-Hours Access Detection",
            description=(
                "Alert when users access AWS console or make sensitive API calls outside of "
                "normal business hours, which may indicate compromised credentials."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.signin"],
                    "detail-type": ["AWS Console Sign In via CloudTrail"],
                    "detail": {
                        "eventName": ["ConsoleLogin"],
                        "responseElements": {
                            "ConsoleLogin": ["Success"]
                        }
                    }
                },
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Off-hours console access detection for T1078

Parameters:
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
  # Step 1: EventBridge rule for console logins
  OffHoursLoginRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1078-OffHoursConsoleAccess
      Description: Detect console logins outside business hours
      EventPattern:
        source:
          - aws.signin
        detail-type:
          - "AWS Console Sign In via CloudTrail"
        detail:
          eventName:
            - ConsoleLogin
          responseElements:
            ConsoleLogin:
              - Success
      State: ENABLED
      Targets:
        - Id: SNSAlert
          Arn: !Ref SNSTopicArn

  # Step 2: Lambda function to check if login is outside business hours
  OffHoursCheckFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.11
      Handler: index.handler
      Role: !GetAtt OffHoursCheckRole.Arn
      Code:
        ZipFile: |
          import json
          import boto3
          from datetime import datetime

          def handler(event, context):
              # Parse login time (customize hours for your organisation)
              login_time = datetime.fromisoformat(event['detail']['eventTime'].replace('Z', '+00:00'))
              hour = login_time.hour
              day_of_week = login_time.weekday()

              # Check if outside business hours (M-F 8am-6pm UTC)
              if day_of_week >= 5 or hour < 8 or hour >= 18:
                  sns = boto3.client('sns')
                  sns.publish(
                      TopicArn=event['detail']['responseElements']['ConsoleLogin'],
                      Subject='Off-Hours AWS Login',
                      Message=f"User {event['detail']['userIdentity']['arn']} logged in at {login_time}"
                  )

              return {'statusCode': 200}

  OffHoursCheckRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: SNSPublish
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: sns:Publish
                Resource: !Ref SNSTopicArn''',
                terraform_template='''# AWS Off-hours access detection for T1078

variable "sns_topic_arn" {
  type        = string
  description = "SNS topic ARN for alerts"
}

# Step 1: EventBridge rule for console logins
resource "aws_cloudwatch_event_rule" "off_hours_login" {
  name        = "T1078-OffHoursConsoleAccess"
  description = "Detect console logins outside business hours"

  event_pattern = jsonencode({
    source      = ["aws.signin"]
    detail-type = ["AWS Console Sign In via CloudTrail"]
    detail = {
      eventName = ["ConsoleLogin"]
      responseElements = {
        ConsoleLogin = ["Success"]
      }
    }
  })
}

# Step 2: Route to SNS (note: add Lambda for time filtering in production)
resource "aws_cloudwatch_event_target" "sns" {
  rule      = aws_cloudwatch_event_rule.off_hours_login.name
  target_id = "SNSAlert"
  arn       = var.sns_topic_arn
}''',
                alert_severity="medium",
                alert_title="Off-Hours Console Login",
                alert_description_template=(
                    "User {user} logged into AWS console at {timestamp}, "
                    "which is outside normal business hours. Source IP: {source_ip}. "
                    "User agent: {user_agent}."
                ),
                investigation_steps=[
                    "Verify if the user has a legitimate reason to work outside hours (on-call, different timezone)",
                    "Check if the user is in a different geographical location",
                    "Review all actions taken during the session",
                    "Compare with user's historical login patterns",
                    "Check for sensitive API calls during the off-hours session",
                    "Verify MFA was used for authentication"
                ],
                containment_actions=[
                    "Contact the user immediately via out-of-band communication (phone, corporate messaging)",
                    "If unverified, disable the user's access and invalidate sessions",
                    "Review and revert any changes made during the session",
                    "Implement time-based access controls via IAM policies"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.HIGH,
            false_positive_tuning="Create exceptions for on-call personnel, users in different timezones, and during incident response; adjust business hours definition",
            detection_coverage="35% - catches credential use from different timezones but misses same-timezone attacks",
            evasion_considerations="Attackers aware of business hours may time their access accordingly; VPNs can mask timezone indicators",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "EventBridge configured"]
        ),

        # Strategy 4: AWS First-Time API Caller
        DetectionStrategy(
            strategy_id="t1078-aws-first-time-api",
            name="First-Time Sensitive API Caller Detection",
            description=(
                "Detect when a user calls sensitive APIs (IAM, KMS, Secrets Manager, EC2, S3) "
                "for the first time, which may indicate credential compromise and reconnaissance."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.arn as user, eventSource, eventName,
       sourceIPAddress, userAgent
| filter eventSource in ["iam.amazonaws.com", "kms.amazonaws.com",
    "secretsmanager.amazonaws.com", "ec2.amazonaws.com", "s3.amazonaws.com"]
| filter eventName in ["CreateUser", "CreateAccessKey", "AttachUserPolicy",
    "AttachRolePolicy", "CreateKey", "Decrypt", "GetSecretValue",
    "CreateSecret", "RunInstances", "CreateSnapshot", "GetObject"]
| stats count(*) as call_count,
        earliest(@timestamp) as first_seen,
        latest(@timestamp) as last_seen,
        count_distinct(sourceIPAddress) as unique_ips
  by user, eventName
| filter call_count = 1 and first_seen > ago(24h)
| sort first_seen desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: First-time sensitive API detection for T1078

Parameters:
  CloudTrailLogGroup:
    Type: String
  SNSTopicArn:
    Type: String

Resources:
  # Step 1: Metric filter for sensitive APIs
  SensitiveAPIFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: >-
        { ($.eventSource = "iam.amazonaws.com" && ($.eventName = "CreateUser" ||
        $.eventName = "CreateAccessKey" || $.eventName = "AttachUserPolicy")) ||
        ($.eventSource = "kms.amazonaws.com" && ($.eventName = "Decrypt" || $.eventName = "CreateKey")) ||
        ($.eventSource = "secretsmanager.amazonaws.com" && $.eventName = "GetSecretValue") }
      MetricTransformations:
        - MetricName: SensitiveAPICall
          MetricNamespace: Security/T1078
          MetricValue: "1"

  # Step 2: Alarm for sensitive API calls
  SensitiveAPIAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1078-FirstTimeSensitiveAPI
      AlarmDescription: First-time sensitive API call detected
      MetricName: SensitiveAPICall
      Namespace: Security/T1078
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn''',
                terraform_template='''# AWS First-time sensitive API detection for T1078

variable "cloudtrail_log_group" {
  type = string
}

variable "sns_topic_arn" {
  type = string
}

# Step 1: Metric filter for sensitive APIs
resource "aws_cloudwatch_log_metric_filter" "sensitive_api" {
  name           = "sensitive-api-calls"
  log_group_name = var.cloudtrail_log_group

  pattern = <<-PATTERN
    { ($.eventSource = "iam.amazonaws.com" && ($.eventName = "CreateUser" ||
    $.eventName = "CreateAccessKey" || $.eventName = "AttachUserPolicy")) ||
    ($.eventSource = "kms.amazonaws.com" && ($.eventName = "Decrypt" || $.eventName = "CreateKey")) ||
    ($.eventSource = "secretsmanager.amazonaws.com" && $.eventName = "GetSecretValue") }
  PATTERN

  metric_transformation {
    name      = "SensitiveAPICall"
    namespace = "Security/T1078"
    value     = "1"
  }
}

# Step 2: Alarm for sensitive API calls
resource "aws_cloudwatch_metric_alarm" "sensitive_api" {
  alarm_name          = "T1078-FirstTimeSensitiveAPI"
  alarm_description   = "First-time sensitive API call detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SensitiveAPICall"
  namespace           = "Security/T1078"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [var.sns_topic_arn]
}''',
                alert_severity="medium",
                alert_title="First-Time Sensitive API Call",
                alert_description_template=(
                    "User {user} called {eventName} for the first time from IP {sourceIPAddress}. "
                    "This is a sensitive API that could indicate credential compromise and reconnaissance."
                ),
                investigation_steps=[
                    "Verify if the user's role legitimately requires this API access",
                    "Check if this correlates with any recent permission changes or role assignments",
                    "Review the context of the API call (parameters, resources affected, success/failure)",
                    "Look for other unusual activity from this user in the same timeframe",
                    "Check if the source IP is known and expected for this user",
                    "Review the user's historical API usage patterns"
                ],
                containment_actions=[
                    "Review and potentially revoke any resources created or accessed",
                    "Audit permissions granted or keys created during the session",
                    "Implement least-privilege IAM policies",
                    "Enable MFA for sensitive API operations via IAM policy conditions"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Build a baseline of normal API usage per user over 30-90 days; whitelist expected first-time activities",
            detection_coverage="55% - catches new activity patterns that deviate from baseline",
            evasion_considerations="Attackers may gradually expand API usage over time to avoid first-time detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=["CloudTrail enabled", "Baseline period for comparison", "CloudTrail logs in CloudWatch"]
        ),

        # Strategy 5: GCP Anomalous Login Detection
        DetectionStrategy(
            strategy_id="t1078-gcp-login",
            name="GCP Anomalous Login Detection",
            description=(
                "Detect suspicious login activity to GCP including impossible travel, "
                "unusual locations, and multiple failed authentication attempts."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="google.login.LoginService.loginSuccess"
OR protoPayload.methodName="google.login.LoginService.loginFailure"
OR protoPayload.methodName="google.login.LoginService.logout"''',
                gcp_terraform_template='''# GCP: Anomalous login detection for T1078

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Valid Accounts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Step 2: Log-based metric for login activity
resource "google_logging_metric" "login_activity" {
  name   = "valid-accounts-login-activity"
  filter = <<-EOT
    protoPayload.methodName="google.login.LoginService.loginSuccess"
    OR protoPayload.methodName="google.login.LoginService.loginFailure"
  EOT
  project = var.project_id

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User email"
    }
  }

  label_extractors = {
    "user" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert policy for suspicious login patterns
resource "google_monitoring_alert_policy" "login_anomaly" {
  display_name = "T1078: Suspicious Login Activity"
  combiner     = "OR"
  project      = var.project_id

  conditions {
    display_name = "High volume login attempts"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.login_activity.name}\" AND resource.type=\"audited_resource\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 10
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "86400s"
  }
}''',
                alert_severity="high",
                alert_title="GCP: Suspicious Login Activity",
                alert_description_template=(
                    "Suspicious login activity detected for user {user}. "
                    "Multiple login attempts or anomalous pattern detected."
                ),
                investigation_steps=[
                    "Review login source IP addresses and geolocations",
                    "Check for impossible travel patterns",
                    "Verify if user recognises the login attempts",
                    "Review all API activity following successful logins",
                    "Check for MFA bypass attempts",
                    "Review admin activity logs for privilege escalation"
                ],
                containment_actions=[
                    "Suspend the user account if compromise is confirmed",
                    "Revoke all active sessions and OAuth tokens",
                    "Reset user password with out-of-band verification",
                    "Enable mandatory 2FA for the account",
                    "Review and revoke any service account keys created",
                    "Audit recent IAM policy changes"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known VPN endpoints, adjust thresholds based on organisation size, exclude service accounts",
            detection_coverage="60% - covers login anomalies and brute force patterns",
            evasion_considerations="Slow authentication attempts over time may evade thresholds",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["Cloud Audit Logs enabled", "Login audit logs enabled"]
        ),

        # Strategy 6: GCP Service Account Key Usage
        DetectionStrategy(
            strategy_id="t1078-gcp-sa-key",
            name="GCP Service Account Key Monitoring",
            description=(
                "Monitor for service account key creation and usage patterns that may "
                "indicate credential compromise or misuse of service accounts."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"google.iam.admin.v1.CreateServiceAccountKey"
OR protoPayload.methodName=~"google.iam.admin.v1.DeleteServiceAccountKey"
OR (protoPayload.authenticationInfo.principalEmail=~"gserviceaccount.com$"
    AND protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog")''',
                gcp_terraform_template='''# GCP: Service account key monitoring for T1078

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Service Accounts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Step 2: Log-based metric for service account key operations
resource "google_logging_metric" "sa_key_operations" {
  name   = "service-account-key-operations"
  filter = <<-EOT
    protoPayload.methodName=~"google.iam.admin.v1.CreateServiceAccountKey"
    OR protoPayload.methodName=~"google.iam.admin.v1.DeleteServiceAccountKey"
  EOT
  project = var.project_id

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "actor"
      value_type  = "STRING"
      description = "Principal performing the operation"
    }
    labels {
      key         = "operation"
      value_type  = "STRING"
      description = "Operation type"
    }
  }

  label_extractors = {
    "actor"     = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
    "operation" = "EXTRACT(protoPayload.methodName)"
  }
}

# Step 3: Alert policy for service account key operations
resource "google_monitoring_alert_policy" "sa_key_alert" {
  display_name = "T1078: Service Account Key Operations"
  combiner     = "OR"
  project      = var.project_id

  conditions {
    display_name = "Service account key created or deleted"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_key_operations.name}\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  documentation {
    content   = "Service account key operation detected. Review for unauthorised access."
    mime_type = "text/markdown"
  }
}''',
                alert_severity="high",
                alert_title="GCP: Service Account Key Operation",
                alert_description_template=(
                    "Service account key operation detected: {operation} by {actor}. "
                    "Review for unauthorised credential creation or deletion."
                ),
                investigation_steps=[
                    "Identify which service account key was created or deleted",
                    "Verify if the operation was authorised via change management",
                    "Check the principal who performed the operation",
                    "Review all API calls made using service account keys",
                    "Audit service account permissions and usage patterns",
                    "Check for exfiltration of key material"
                ],
                containment_actions=[
                    "Delete unauthorised service account keys immediately",
                    "Rotate legitimate service account keys as a precaution",
                    "Review and restrict service account key creation permissions",
                    "Enable key rotation policies",
                    "Implement workload identity federation to eliminate keys",
                    "Audit all resources accessed by the service account"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Integrate with change management; whitelist automated deployment systems; alert on user-created keys only",
            detection_coverage="90% - excellent coverage for service account credential operations",
            evasion_considerations="Attackers may use existing keys rather than creating new ones",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled", "Admin Activity logs enabled"]
        ),

        # Strategy 7: GCP Impossible Travel
        DetectionStrategy(
            strategy_id="t1078-gcp-impossible-travel",
            name="GCP Impossible Travel Detection",
            description=(
                "Detect when the same GCP account is used from geographically distant "
                "locations in a short timeframe, indicating possible credential compromise."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
protoPayload.authenticationInfo.principalEmail!=""
NOT protoPayload.authenticationInfo.principalEmail=~"gserviceaccount.com$"''',
                gcp_terraform_template='''# GCP: Impossible travel detection for T1078
# Note: Full implementation requires Security Command Centre or custom analysis

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts - Impossible Travel"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
  project = var.project_id
}

# Step 2: Log sink to BigQuery for analysis
resource "google_logging_project_sink" "audit_logs_sink" {
  name        = "audit-logs-impossible-travel"
  destination = "bigquery.googleapis.com/projects/${var.project_id}/datasets/security_logs"
  filter      = <<-EOT
    protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
    protoPayload.authenticationInfo.principalEmail!=""
    NOT protoPayload.authenticationInfo.principalEmail=~"gserviceaccount.com$"
  EOT
  project     = var.project_id

  unique_writer_identity = true
}

# Step 3: BigQuery dataset for log analysis
resource "google_bigquery_dataset" "security_logs" {
  dataset_id  = "security_logs"
  description = "Security logs for impossible travel analysis"
  location    = "EU"
  project     = var.project_id

  default_table_expiration_ms = 7776000000 # 90 days
}

# Note: Impossible travel analysis requires custom SQL queries or Security Command Centre
# Example BigQuery query to run periodically:
# SELECT
#   protopayload_auditlog.authenticationInfo.principalEmail,
#   timestamp,
#   protopayload_auditlog.requestMetadata.callerIp,
#   COUNT(DISTINCT protopayload_auditlog.requestMetadata.callerIp) OVER (
#     PARTITION BY protopayload_auditlog.authenticationInfo.principalEmail
#     ORDER BY timestamp
#     RANGE BETWEEN INTERVAL 1 HOUR PRECEDING AND CURRENT ROW
#   ) as unique_ips_1h
# FROM `project.security_logs.cloudaudit_googleapis_com_activity_*`
# WHERE unique_ips_1h > 1''',
                alert_severity="high",
                alert_title="GCP: Impossible Travel Detected",
                alert_description_template=(
                    "User {user} accessed GCP from multiple geographic locations within a short timeframe. "
                    "This may indicate credential compromise."
                ),
                investigation_steps=[
                    "Identify all source IPs and geolocate them",
                    "Calculate travel time between locations",
                    "Check if IPs are VPN endpoints or cloud shell instances",
                    "Review all API activity from each location",
                    "Contact the user to verify access from all locations",
                    "Check for MFA usage on all sessions"
                ],
                containment_actions=[
                    "Suspend the user account immediately",
                    "Revoke all active OAuth tokens and sessions",
                    "Reset password with out-of-band verification",
                    "Enable context-aware access policies",
                    "Review and revert unauthorised changes",
                    "Enable Security Command Centre for advanced detection"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist Cloud Shell IPs, VPN endpoints, and legitimate cloud infrastructure; adjust time thresholds",
            detection_coverage="40% - requires additional tooling (Security Command Centre) for full coverage",
            evasion_considerations="Attackers using VPNs in expected regions or Cloud Shell can evade geographic detection",
            implementation_effort=EffortLevel.HIGH,
            implementation_time="3-4 hours",
            estimated_monthly_cost="$20-50 (includes BigQuery storage and queries)",
            prerequisites=["Cloud Audit Logs enabled", "BigQuery for log analysis", "Optional: Security Command Centre"]
        )
    ],

    recommended_order=[
        "t1078-aws-guardduty",
        "t1078-gcp-login",
        "t1078-gcp-sa-key",
        "t1078-aws-impossible-travel",
        "t1078-aws-first-time-api",
        "t1078-aws-off-hours",
        "t1078-gcp-impossible-travel"
    ],
    total_effort_hours=12.0,
    coverage_improvement="+30% improvement for Initial Access and Persistence tactics"
)
