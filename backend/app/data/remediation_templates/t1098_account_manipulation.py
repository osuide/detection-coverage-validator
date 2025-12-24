"""
T1098 - Account Manipulation

Adversaries may manipulate accounts to maintain access to victim systems.
"""

from .template_loader import (
    RemediationTemplate,
    ThreatContext,
    DetectionStrategy,
    DetectionImplementation,
    DetectionType,
    EffortLevel,
    FalsePositiveRate,
)

TEMPLATE = RemediationTemplate(
    technique_id="T1098",
    technique_name="Account Manipulation",
    tactic_ids=["TA0003"],
    mitre_url="https://attack.mitre.org/techniques/T1098/",
    threat_context=ThreatContext(
        description=(
            "Adversaries may manipulate accounts to maintain access to victim systems. "
            "This includes adding credentials to existing accounts, modifying permissions, "
            "creating new access keys, or adding accounts to privileged groups."
        ),
        attacker_goal="Establish persistent access by modifying or creating account credentials",
        why_technique=[
            "Provides backup access if primary credentials are revoked",
            "Enables privilege escalation through permission changes",
            "Creates additional attack paths that may go unnoticed",
            "Access keys can be used externally without console access",
            "Changes may persist through normal password rotations",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Account manipulation is a critical persistence technique. "
            "Changes to IAM can provide long-term access and enable privilege escalation. "
            "Detection is essential to prevent attacker persistence."
        ),
        business_impact=[
            "Persistent unauthorised access to cloud resources",
            "Privilege escalation leading to full environment compromise",
            "Difficulty in fully remediating incidents",
            "Compliance violations for unauthorised access changes",
            "Potential for future attacks using hidden access",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1530", "T1537", "T1562"],
        often_follows=["T1078", "T1110"],
    ),
    detection_strategies=[
        # Strategy 1: GuardDuty IAM Anomalies
        DetectionStrategy(
            strategy_id="t1098-guardduty",
            name="GuardDuty IAM Anomaly Detection",
            description=(
                "AWS GuardDuty detects anomalous IAM activity including unusual "
                "API calls and potential credential manipulation."
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Persistence:IAMUser/AnomalousBehavior",
                    "PrivilegeEscalation:IAMUser/AnomalousBehavior",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty + email alerts for IAM anomalies

Parameters:
  AlertEmail:
    Type: String

Resources:
  # Step 1: Enable GuardDuty (detects IAM anomalies automatically)
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true

  # Step 2: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 3: Route IAM findings to email
  IAMFindingsRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.guardduty]
        detail:
          type:
            - prefix: "Persistence:IAMUser"
            - prefix: "PrivilegeEscalation:IAMUser"
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
                terraform_template="""# GuardDuty + email alerts for IAM anomalies

variable "alert_email" {
  type = string
}

# Step 1: Enable GuardDuty (detects IAM anomalies automatically)
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 2: Create SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "guardduty-iam-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 3: Route IAM findings to email
resource "aws_cloudwatch_event_rule" "iam_findings" {
  name = "guardduty-iam-alerts"
  event_pattern = jsonencode({
    source = ["aws.guardduty"]
    detail = {
      type = [
        { prefix = "Persistence:IAMUser" },
        { prefix = "PrivilegeEscalation:IAMUser" },
        { prefix = "CredentialAccess:IAMUser" }
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.iam_findings.name
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
                alert_title="GuardDuty: IAM Anomaly Detected",
                alert_description_template=(
                    "GuardDuty detected anomalous IAM activity: {finding_type}. "
                    "Principal: {principal}. This may indicate account manipulation."
                ),
                investigation_steps=[
                    "Review the specific IAM changes made by the principal",
                    "Check if new access keys or credentials were created",
                    "Verify if permissions were escalated",
                    "Review the principal's recent activity pattern",
                    "Contact the account owner to verify legitimacy",
                ],
                containment_actions=[
                    "Revoke any newly created access keys",
                    "Remove unauthorised permission changes",
                    "Disable the affected IAM user if compromised",
                    "Review and restrict IAM permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist known automation accounts and admin roles",
            detection_coverage="60% - covers anomalous IAM behaviour",
            evasion_considerations="Slow, gradual permission changes may evade detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events",
            prerequisites=["AWS account with appropriate IAM permissions"],
        ),
        # Strategy 2: Access Key Creation
        DetectionStrategy(
            strategy_id="t1098-access-key-creation",
            name="IAM Access Key Creation Monitoring",
            description=(
                "Monitor for creation of new IAM access keys, which could provide "
                "persistent API access to adversaries."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["iam.amazonaws.com"],
                        "eventName": [
                            "CreateAccessKey",
                            "CreateLoginProfile",
                            "UpdateLoginProfile",
                        ],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: IAM access key creation monitoring

Parameters:
  SNSTopicArn:
    Type: String

Resources:
  AccessKeyCreationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1098-AccessKeyCreation
      Description: Detect IAM access key and credential creation
      EventPattern:
        source:
          - aws.iam
        detail-type:
          - "AWS API Call via CloudTrail"
        detail:
          eventSource:
            - iam.amazonaws.com
          eventName:
            - CreateAccessKey
            - CreateLoginProfile
            - UpdateLoginProfile
      State: ENABLED
      Targets:
        - Id: SNSAlert
          Arn: !Ref SNSTopicArn""",
                alert_severity="high",
                alert_title="IAM Credential Creation Detected",
                alert_description_template=(
                    "User {user} performed {eventName} for account {targetUser}. "
                    "Source IP: {sourceIPAddress}. Verify this is an authorised change."
                ),
                investigation_steps=[
                    "Verify if the credential creation was authorised",
                    "Check who requested the new credentials",
                    "Review the target account's current access keys",
                    "Determine if this follows normal provisioning procedures",
                    "Check for other suspicious activity from the source IP",
                ],
                containment_actions=[
                    "Delete any unauthorised access keys",
                    "Disable login profiles created without authorisation",
                    "Review and update IAM policies for least privilege",
                    "Implement SCP controls for credential creation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist automated provisioning systems; use change management tickets",
            detection_coverage="95% - complete coverage for credential creation",
            evasion_considerations="Attackers may use existing overly permissive accounts",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "EventBridge configured"],
        ),
        # Strategy 3: Permission Escalation
        DetectionStrategy(
            strategy_id="t1098-permission-escalation",
            name="IAM Permission Escalation Detection",
            description=(
                "Monitor for IAM policy changes that could indicate privilege escalation, "
                "including attaching policies or adding users to groups."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["iam.amazonaws.com"],
                        "eventName": [
                            "AttachUserPolicy",
                            "AttachRolePolicy",
                            "AttachGroupPolicy",
                            "PutUserPolicy",
                            "PutRolePolicy",
                            "PutGroupPolicy",
                            "AddUserToGroup",
                            "CreatePolicyVersion",
                            "SetDefaultPolicyVersion",
                        ],
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: IAM permission escalation detection

Parameters:
  SNSTopicArn:
    Type: String

Resources:
  PermissionEscalationRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1098-PermissionEscalation
      Description: Detect IAM permission changes
      EventPattern:
        source:
          - aws.iam
        detail-type:
          - "AWS API Call via CloudTrail"
        detail:
          eventSource:
            - iam.amazonaws.com
          eventName:
            - AttachUserPolicy
            - AttachRolePolicy
            - AttachGroupPolicy
            - PutUserPolicy
            - PutRolePolicy
            - PutGroupPolicy
            - AddUserToGroup
            - CreatePolicyVersion
            - SetDefaultPolicyVersion
      State: ENABLED
      Targets:
        - Id: SNSAlert
          Arn: !Ref SNSTopicArn""",
                alert_severity="high",
                alert_title="IAM Permission Change Detected",
                alert_description_template=(
                    "User {user} performed {eventName}. Target: {target}. "
                    "This may indicate privilege escalation. Source IP: {sourceIPAddress}."
                ),
                investigation_steps=[
                    "Review the specific permissions added",
                    "Determine if the change was authorised via change management",
                    "Check if sensitive permissions (IAM, KMS, etc.) were added",
                    "Verify the principal making the change",
                    "Look for patterns indicating privilege escalation chain",
                ],
                containment_actions=[
                    "Revert unauthorised permission changes",
                    "Review all policies attached to the affected entity",
                    "Implement approval workflows for IAM changes",
                    "Consider using AWS Organisations SCPs to limit changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Integrate with change management; whitelist IaC deployment roles",
            detection_coverage="90% - excellent coverage for permission changes",
            evasion_considerations="Using existing permissions rather than adding new ones",
            implementation_effort=EffortLevel.LOW,
            implementation_time="1 hour",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "EventBridge configured"],
        ),
        # Strategy 4: Comprehensive IAM Change Monitoring
        DetectionStrategy(
            strategy_id="t1098-iam-changes",
            name="Comprehensive IAM Change Analysis",
            description=(
                "Use CloudWatch Logs Insights to analyse patterns of IAM changes "
                "that may indicate account manipulation."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as user, eventName, sourceIPAddress,
       requestParameters.userName as targetUser, requestParameters.roleName as targetRole,
       requestParameters.policyArn as policy
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["CreateUser", "CreateRole", "CreateAccessKey", "CreateLoginProfile",
    "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
    "AddUserToGroup", "UpdateAssumeRolePolicy"]
| stats count(*) as change_count, count_distinct(eventName) as unique_actions
  by user, sourceIPAddress, bin(1h) as hour_window
| filter change_count >= 5 or unique_actions >= 3
| sort change_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Comprehensive IAM change monitoring

Parameters:
  CloudTrailLogGroup:
    Type: String
  SNSTopicArn:
    Type: String

Resources:
  IAMChangeMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "iam.amazonaws.com" && ($.eventName = "CreateUser" || $.eventName = "CreateAccessKey" || $.eventName = "AttachUserPolicy" || $.eventName = "AttachRolePolicy") }'
      MetricTransformations:
        - MetricName: IAMChanges
          MetricNamespace: Security/T1098
          MetricValue: "1"

  IAMChangeAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1098-ExcessiveIAMChanges
      AlarmDescription: Multiple IAM changes detected in short time
      MetricName: IAMChanges
      Namespace: Security/T1098
      Statistic: Sum
      Period: 3600
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SNSTopicArn""",
                alert_severity="high",
                alert_title="Excessive IAM Changes Detected",
                alert_description_template=(
                    "User {user} made {change_count} IAM changes ({unique_actions} unique actions) in 1 hour. "
                    "Source IP: {sourceIPAddress}. This may indicate account manipulation."
                ),
                investigation_steps=[
                    "List all IAM changes made by the user in the time window",
                    "Determine if changes were part of authorised provisioning",
                    "Check for patterns (e.g., creating user then escalating permissions)",
                    "Review the resources created or modified",
                    "Verify the source IP is expected for administrative tasks",
                ],
                containment_actions=[
                    "Temporarily restrict the user's IAM permissions",
                    "Review and revert unauthorised changes",
                    "Implement stricter IAM permission boundaries",
                    "Enable IAM Access Analyser for external access detection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal IAM change patterns; exclude IaC deployments",
            detection_coverage="85% - catches patterns of account manipulation",
            evasion_considerations="Very slow, gradual changes spread over time",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail enabled", "CloudTrail logs in CloudWatch"],
        ),
    ],
    recommended_order=[
        "t1098-guardduty",
        "t1098-access-key-creation",
        "t1098-permission-escalation",
        "t1098-iam-changes",
    ],
    total_effort_hours=4.5,
    coverage_improvement="+35% improvement for Persistence tactic",
)
