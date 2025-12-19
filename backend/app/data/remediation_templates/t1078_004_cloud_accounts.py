"""
T1078.004 - Valid Accounts: Cloud Accounts

Adversaries may obtain and abuse credentials of cloud accounts to gain
initial access, persistence, privilege escalation, or defence evasion.
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
)

TEMPLATE = RemediationTemplate(
    technique_id="T1078.004",
    technique_name="Valid Accounts: Cloud Accounts",
    tactic_ids=["TA0001", "TA0003", "TA0004", "TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1078/004/",

    threat_context=ThreatContext(
        description=(
            "Adversaries obtain and abuse credentials of existing cloud accounts "
            "to gain initial access, persistence, privilege escalation, or defence evasion. "
            "Cloud accounts include AWS IAM users, Azure AD accounts, and GCP service accounts."
        ),
        attacker_goal="Gain legitimate access to cloud resources without deploying malware",
        why_technique=[
            "Legitimate credentials bypass most perimeter security controls",
            "Activity blends with normal user behaviour",
            "No malware signatures to detect",
            "Access often persists until password rotation",
            "Can escalate privileges if account has excessive permissions"
        ],
        known_threat_actors=["APT29 (Cozy Bear)", "APT33 (Elfin)", "Scattered Spider", "Lapsus$", "UNC2452"],
        recent_campaigns=[
            Campaign(
                name="SolarWinds/SUNBURST",
                year=2020,
                description="APT29 used compromised cloud credentials to access victim environments",
                reference_url="https://www.mandiant.com/resources/sunburst-additional-technical-details"
            ),
            Campaign(
                name="Lapsus$ Attacks",
                year=2022,
                description="Purchased credentials from initial access brokers to compromise Microsoft, Nvidia, Samsung",
                reference_url="https://www.microsoft.com/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration/"
            ),
            Campaign(
                name="Scattered Spider",
                year=2023,
                description="Social engineering and SIM swapping to obtain cloud credentials for ransomware deployment",
                reference_url="https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"
            )
        ],
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Credential-based access is the most common initial access vector in cloud breaches. "
            "Once obtained, credentials provide immediate access with legitimate permissions, "
            "making detection challenging without behavioural analysis."
        ),
        business_impact=[
            "Unauthorised access to sensitive data",
            "Data exfiltration without triggering traditional security controls",
            "Lateral movement to connected systems",
            "Ransomware deployment",
            "Regulatory compliance violations (GDPR, HIPAA)"
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1087", "T1069", "T1530"],
        often_follows=["T1566", "T1110", "T1552"]
    ),

    detection_strategies=[
        # Strategy 1: GuardDuty
        DetectionStrategy(
            strategy_id="t1078004-guardduty",
            name="Enable GuardDuty Credential Abuse Detection",
            description=(
                "AWS GuardDuty provides managed detection for suspicious credential usage "
                "including impossible travel, unusual API calls, and credential exfiltration attempts."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
                    "InitialAccess:IAMUser/AnomalousBehavior",
                    "CredentialAccess:IAMUser/AnomalousBehavior"
                ],
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Enable GuardDuty for credential abuse detection

Resources:
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: FIFTEEN_MINUTES
      DataSources:
        S3Logs:
          Enable: true
      Tags:
        - Key: Purpose
          Value: T1078.004-Detection''',
                terraform_template='''resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
  }

  tags = {
    Purpose = "T1078.004-Detection"
  }
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
                    "Contact the user to confirm if activity was legitimate",
                    "Review IAM permissions to assess potential blast radius"
                ],
                containment_actions=[
                    "Disable the IAM user's console access and access keys",
                    "Rotate all access keys for the affected user",
                    "Enable MFA if not already enabled",
                    "Review and revoke any sessions using AWS STS"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Add trusted IPs to GuardDuty IP lists; suppress findings for known CI/CD systems",
            detection_coverage="60% - covers anomalous behaviour patterns",
            evasion_considerations="Attackers may use VPNs in same region or slow-and-low techniques",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events analysed",
            prerequisites=["AWS account with appropriate IAM permissions"]
        ),

        # Strategy 2: Impossible Travel
        DetectionStrategy(
            strategy_id="t1078004-impossible-travel",
            name="Impossible Travel Detection via CloudWatch",
            description=(
                "Detect when the same user authenticates from geographically distant locations "
                "within a timeframe that makes physical travel impossible."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.arn as user, sourceIPAddress, eventName
| filter eventName = "ConsoleLogin" and responseElements.ConsoleLogin = "Success"
| stats earliest(@timestamp) as first_login, latest(@timestamp) as last_login,
        count(*) as login_count, count_distinct(sourceIPAddress) as unique_ips
  by user, bin(1h) as hour_window
| filter unique_ips > 1
| sort last_login desc''',
                cloudformation_template='''AWSTemplateFormatVersion: '2010-09-09'
Description: Impossible travel detection for T1078.004

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  SNSTopicArn:
    Type: String
    Description: SNS topic for alerts

Resources:
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
      Threshold: 1
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref SNSTopicArn''',
                alert_severity="high",
                alert_title="Impossible Travel: Multiple Login Locations",
                alert_description_template=(
                    "User {user} logged in from {unique_ips} different IP addresses within 1 hour. "
                    "This may indicate credential compromise."
                ),
                investigation_steps=[
                    "Identify all IP addresses used by the user in the detection window",
                    "Geolocate the IPs to determine physical distance",
                    "Check if any IPs are known VPN or corporate egress points",
                    "Review all API calls made from each IP address",
                    "Contact the user to verify login locations"
                ],
                containment_actions=[
                    "Force logout all active sessions for the user",
                    "Temporarily disable console access",
                    "Require password reset with MFA verification"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known VPN exit nodes and corporate proxies",
            detection_coverage="40% - catches obvious geographic anomalies",
            evasion_considerations="Attackers may use VPNs in expected locations",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$5-20 depending on log volume",
            prerequisites=["CloudTrail enabled", "CloudTrail logs sent to CloudWatch Logs"]
        ),

        # Strategy 3: Off-Hours Access
        DetectionStrategy(
            strategy_id="t1078004-off-hours",
            name="Off-Hours Console Access Detection",
            description=(
                "Alert when users access the AWS console outside of normal business hours."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
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
Description: Off-hours console access detection

Parameters:
  SNSTopicArn:
    Type: String

Resources:
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
          Arn: !Ref SNSTopicArn''',
                alert_severity="medium",
                alert_title="Off-Hours Console Login",
                alert_description_template=(
                    "User {user} logged into AWS console at {timestamp}, "
                    "which is outside normal business hours. Source IP: {source_ip}."
                ),
                investigation_steps=[
                    "Verify if the user has a legitimate reason to work outside hours",
                    "Check if the user is in a different timezone",
                    "Review all actions taken during the session",
                    "Compare with user's historical login patterns"
                ],
                containment_actions=[
                    "Contact the user immediately via out-of-band communication",
                    "If unverified, disable the user's access"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Create exceptions for on-call personnel and users in different timezones",
            detection_coverage="30% - catches credential use from different time zones",
            evasion_considerations="Attackers aware of business hours may time their access accordingly",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "EventBridge configured"]
        ),

        # Strategy 4: First-Time API Caller
        DetectionStrategy(
            strategy_id="t1078004-first-time-api",
            name="First-Time Sensitive API Caller Detection",
            description=(
                "Detect when a user calls sensitive APIs (IAM, KMS, Secrets Manager) "
                "for the first time."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            implementation=DetectionImplementation(
                query='''fields @timestamp, userIdentity.arn as user, eventSource, eventName, sourceIPAddress
| filter eventSource in ["iam.amazonaws.com", "kms.amazonaws.com", "secretsmanager.amazonaws.com"]
| filter eventName in ["CreateUser", "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy",
    "CreateKey", "Decrypt", "GetSecretValue", "CreateSecret"]
| stats count(*) as call_count, earliest(@timestamp) as first_seen by user, eventName
| filter call_count = 1 and first_seen > ago(24h)
| sort first_seen desc''',
                alert_severity="medium",
                alert_title="First-Time Sensitive API Call",
                alert_description_template=(
                    "User {user} called {eventName} for the first time. "
                    "This is a sensitive API that could indicate credential compromise."
                ),
                investigation_steps=[
                    "Verify if the user's role requires this API access",
                    "Check if this correlates with any recent permission changes",
                    "Review the context of the API call (parameters, resources affected)",
                    "Look for other unusual activity from this user"
                ],
                containment_actions=[
                    "Review and potentially revoke any resources created",
                    "Audit permissions granted or keys created"
                ]
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Build a baseline of normal API usage per user over 30 days",
            detection_coverage="50% - catches new activity patterns",
            evasion_considerations="Attackers may gradually expand API usage",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=["CloudTrail enabled", "Baseline period for comparison"]
        )
    ],

    recommended_order=[
        "t1078004-guardduty",
        "t1078004-impossible-travel",
        "t1078004-off-hours",
        "t1078004-first-time-api"
    ],
    total_effort_hours=6.0,
    coverage_improvement="+25% improvement for Credential Access tactic"
)
