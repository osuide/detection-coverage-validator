"""
T1556 - Modify Authentication Process

Adversaries modify authentication mechanisms and protocols to access credentials
or enable persistent, unauthorised access whilst bypassing standard authentication
controls. In cloud environments, this includes tampering with IAM policies,
conditional access rules, identity provider configurations, and MFA settings.
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
    technique_id="T1556",
    technique_name="Modify Authentication Process",
    tactic_ids=["TA0006", "TA0005", "TA0003"],
    mitre_url="https://attack.mitre.org/techniques/T1556/",
    threat_context=ThreatContext(
        description=(
            "Adversaries modify authentication mechanisms to access credentials or enable "
            "persistent, unauthorised access. In cloud environments, this includes weakening "
            "IAM authentication policies, disabling MFA enforcement, modifying conditional "
            "access policies, tampering with identity provider trust relationships, and "
            "enabling authentication bypass mechanisms. These modifications allow attackers "
            "to maintain access whilst bypassing security controls that would normally detect "
            "or prevent unauthorised authentication."
        ),
        attacker_goal="Bypass or weaken authentication controls to enable persistent access and credential harvesting",
        why_technique=[
            "Bypasses multi-factor authentication requirements",
            "Enables persistent access after initial compromise",
            "Difficult to detect without specific monitoring",
            "Allows access from any location without challenge",
            "Modifications often persist after incident response",
            "Can reveal credentials for lateral movement",
            "Weakens organisation-wide security posture",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="moderate",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Modifying authentication processes represents a critical security compromise, "
            "enabling both credential access and persistent unauthorised access. This technique "
            "removes or bypasses fundamental security controls, significantly increasing breach "
            "impact. Authentication modifications often indicate advanced adversaries with "
            "privileged access and typically enable follow-on attacks including data exfiltration "
            "and lateral movement."
        ),
        business_impact=[
            "Complete bypass of authentication security controls",
            "Persistent unauthorised access to systems and data",
            "Credential harvesting enabling lateral movement",
            "Compliance violations (SOC 2, ISO 27001, PCI DSS)",
            "Difficult to detect and remediate fully",
            "Organisation-wide security posture degradation",
            "Potential for long-term undetected compromise",
        ],
        typical_attack_phase="credential_access",
        often_precedes=["T1078.004", "T1530", "T1110", "T1552"],
        often_follows=["T1078.004", "T1098", "T1528", "T1548"],
    ),
    detection_strategies=[
        # Strategy 1: AWS IAM Authentication Policy Modifications
        DetectionStrategy(
            strategy_id="t1556-aws-iam-auth-policy",
            name="IAM Authentication Policy Weakening Detection",
            description="Detect modifications to IAM policies that weaken authentication requirements or enable authentication bypass.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "PutUserPolicy",
                            "PutRolePolicy",
                            "PutGroupPolicy",
                            "CreatePolicyVersion",
                            "SetDefaultPolicyVersion",
                            "AttachUserPolicy",
                            "AttachRolePolicy",
                            "AttachGroupPolicy",
                            "UpdateAssumeRolePolicy",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IAM authentication policy modifications

Parameters:
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

  # Dead Letter Queue for failed events
  EventDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: T1556-IAMAuthPolicy-DLQ
      MessageRetentionPeriod: 1209600  # 14 days

  # Step 2: EventBridge rule for IAM policy changes
  IAMPolicyChangeRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1556-IAMAuthPolicyChanges
      Description: Alert on IAM policy modifications that may weaken authentication
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - PutUserPolicy
            - PutRolePolicy
            - PutGroupPolicy
            - CreatePolicyVersion
            - SetDefaultPolicyVersion
            - AttachUserPolicy
            - AttachRolePolicy
            - AttachGroupPolicy
            - UpdateAssumeRolePolicy
      State: ENABLED
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt EventDLQ.Arn

  # Step 3: Topic policy
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt IAMPolicyChangeRule.Arn""",
                terraform_template="""# Detect IAM authentication policy modifications

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "iam_auth_policy_alerts" {
  name = "iam-auth-policy-changes"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.iam_auth_policy_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for failed events
resource "aws_sqs_queue" "event_dlq" {
  name                      = "iam-auth-policy-dlq"
  message_retention_seconds = 1209600  # 14 days
}

# SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
data "aws_iam_policy_document" "eventbridge_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sqs_queue.event_dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.iam_policy_change.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq_policy" {
  queue_url = aws_sqs_queue.event_dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# Step 2: EventBridge rule for IAM policy changes
resource "aws_cloudwatch_event_rule" "iam_policy_change" {
  name        = "iam-auth-policy-modifications"
  description = "Alert on IAM policy modifications that may weaken authentication"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
        "UpdateAssumeRolePolicy"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.iam_policy_change.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.iam_auth_policy_alerts.arn

  retry_policy {
    maximum_retry_attempts = 8
    maximum_event_age_in_seconds      = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.event_dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
  }

}

# Step 3: Topic policy
data "aws_caller_identity" "current" {}

resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.iam_auth_policy_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.iam_auth_policy_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.iam_policy_change.arn
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="IAM Authentication Policy Modified",
                alert_description_template=(
                    "IAM policy modified: {eventName} on {resourceName} by {actor}. "
                    "This may indicate authentication bypass or weakening attempt."
                ),
                investigation_steps=[
                    "Review the specific policy changes made (requestParameters)",
                    "Check if MFA requirements were removed or weakened",
                    "Verify if the modification was authorised",
                    "Identify who made the change (userIdentity)",
                    "Review source IP and user agent for anomalies",
                    "Check for suspicious conditions in assume role policies",
                    "Look for overly permissive trust relationships",
                    "Review other IAM changes by the same actor",
                ],
                containment_actions=[
                    "Revert unauthorised policy changes immediately",
                    "Re-enable MFA requirements if removed",
                    "Disable compromised IAM principal's access",
                    "Rotate credentials for affected users/roles",
                    "Review and remove suspicious trust relationships",
                    "Enable AWS IAM Access Analyzer",
                    "Implement SCPs to prevent policy tampering",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known administrative accounts during planned changes; suppress during IaC deployments",
            detection_coverage="95% - catches all IAM policy modification API calls",
            evasion_considerations="Attackers may make gradual changes; monitor policy content, not just API calls",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "IAM events logged"],
        ),
        # Strategy 2: AWS STS Assume Role Without MFA
        DetectionStrategy(
            strategy_id="t1556-aws-assume-role-no-mfa",
            name="AssumeRole Without MFA Detection",
            description="Detect when privileged roles are assumed without MFA, potentially indicating authentication bypass.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn as actor, requestParameters.roleArn, userIdentity.sessionContext.attributes.mfaAuthenticated, sourceIPAddress
| filter eventName = "AssumeRole"
| filter userIdentity.sessionContext.attributes.mfaAuthenticated = "false" or ispresent(userIdentity.sessionContext.attributes.mfaAuthenticated) = 0
| filter requestParameters.roleArn like /Admin|Power|Privileged/
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor AssumeRole calls without MFA for privileged roles

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
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

  # Step 2: Metric filter for AssumeRole without MFA
  AssumeRoleNoMFAFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ ($.eventName = "AssumeRole") && (($.userIdentity.sessionContext.attributes.mfaAuthenticated = "false") || ($.userIdentity.sessionContext.attributes.mfaAuthenticated NOT EXISTS)) && ($.requestParameters.roleArn = "*Admin*" || $.requestParameters.roleArn = "*Power*") }'
      MetricTransformations:
        - MetricName: AssumeRoleWithoutMFA
          MetricNamespace: Security/T1556
          MetricValue: "1"

  # Step 3: Alarm for privileged AssumeRole without MFA
  AssumeRoleNoMFAAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1556-AssumeRoleWithoutMFA
      AlarmDescription: Alert when privileged roles assumed without MFA
      MetricName: AssumeRoleWithoutMFA
      Namespace: Security/T1556
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Monitor AssumeRole calls without MFA for privileged roles

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "assume_role_no_mfa_alerts" {
  name = "assume-role-no-mfa-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.assume_role_no_mfa_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for AssumeRole without MFA
resource "aws_cloudwatch_log_metric_filter" "assume_role_no_mfa" {
  name           = "assume-role-without-mfa"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ ($.eventName = \"AssumeRole\") && (($.userIdentity.sessionContext.attributes.mfaAuthenticated = \"false\") || ($.userIdentity.sessionContext.attributes.mfaAuthenticated NOT EXISTS)) && ($.requestParameters.roleArn = \"*Admin*\" || $.requestParameters.roleArn = \"*Power*\") }"

  metric_transformation {
    name      = "AssumeRoleWithoutMFA"
    namespace = "Security/T1556"
    value     = "1"
  }
}

# Step 3: Alarm for privileged AssumeRole without MFA
resource "aws_cloudwatch_metric_alarm" "assume_role_no_mfa" {
  alarm_name          = "assume-role-without-mfa"
  metric_name         = "AssumeRoleWithoutMFA"
  namespace           = "Security/T1556"
  statistic           = "Sum"
  period              = 300
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.assume_role_no_mfa_alerts.arn]
  alarm_description   = "Privileged role assumed without MFA authentication"
}""",
                alert_severity="high",
                alert_title="Privileged Role Assumed Without MFA",
                alert_description_template=(
                    "Role {roleArn} assumed without MFA by {actor} from {sourceIPAddress}. "
                    "This may indicate authentication bypass or policy weakening."
                ),
                investigation_steps=[
                    "Verify if the assume role action was authorised",
                    "Check if the role's trust policy requires MFA",
                    "Review recent changes to the role's trust policy",
                    "Identify the principal that assumed the role",
                    "Check source IP and geolocation for anomalies",
                    "Review actions taken with the assumed role",
                    "Verify if MFA requirement was recently removed",
                ],
                containment_actions=[
                    "Revoke active sessions for the assumed role",
                    "Update role trust policy to require MFA",
                    "Disable the principal that assumed the role",
                    "Review and revert unauthorised trust policy changes",
                    "Enable SCP to enforce MFA for privileged roles",
                    "Audit all role assumption activity",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist service-to-service role assumptions; exclude automation accounts with compensating controls",
            detection_coverage="90% - catches privileged role assumptions without MFA",
            evasion_considerations="Attackers may use service roles or modify trust policies to exclude MFA requirements",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "CloudWatch Logs integration"],
        ),
        # Strategy 3: AWS Identity Provider Modifications
        DetectionStrategy(
            strategy_id="t1556-aws-idp-modify",
            name="Identity Provider Configuration Changes",
            description="Detect modifications to SAML/OIDC identity providers that could enable authentication bypass.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "CreateSAMLProvider",
                            "UpdateSAMLProvider",
                            "DeleteSAMLProvider",
                            "CreateOpenIDConnectProvider",
                            "UpdateOpenIDConnectProviderThumbprint",
                            "AddClientIDToOpenIDConnectProvider",
                            "DeleteOpenIDConnectProvider",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect identity provider configuration changes

Parameters:
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

  # Dead Letter Queue for failed events
  EventDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: T1556-IdentityProvider-DLQ
      MessageRetentionPeriod: 1209600  # 14 days

  # Step 2: EventBridge rule for IdP changes
  IdPChangeRule:
    Type: AWS::Events::Rule
    Properties:
      Name: T1556-IdentityProviderChanges
      Description: Alert on identity provider modifications
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - CreateSAMLProvider
            - UpdateSAMLProvider
            - DeleteSAMLProvider
            - CreateOpenIDConnectProvider
            - UpdateOpenIDConnectProviderThumbprint
            - AddClientIDToOpenIDConnectProvider
            - DeleteOpenIDConnectProvider
      State: ENABLED
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic
          RetryPolicy:
            MaximumRetryAttempts: 8
            MaximumEventAge: 3600
          DeadLetterConfig:
            Arn: !GetAtt EventDLQ.Arn

  # Step 3: Topic policy
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
            Resource: !Ref AlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt IdPChangeRule.Arn""",
                terraform_template="""# Detect identity provider configuration changes

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "idp_change_alerts" {
  name = "identity-provider-changes"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.idp_change_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Dead Letter Queue for failed events
resource "aws_sqs_queue" "event_dlq" {
  name                      = "identity-provider-dlq"
  message_retention_seconds = 1209600  # 14 days
}

# SQS Queue Policy for EventBridge DLQ (CRITICAL)
# Without this, EventBridge cannot send failed events to the DLQ
data "aws_iam_policy_document" "idp_dlq_policy" {
  statement {
    sid     = "AllowEventBridgeToSendToDLQ"
    effect  = "Allow"
    actions = ["sqs:SendMessage"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sqs_queue.event_dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.idp_change.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "idp_dlq_policy" {
  queue_url = aws_sqs_queue.event_dlq.url
  policy    = data.aws_iam_policy_document.idp_dlq_policy.json
}

# Step 2: EventBridge rule for IdP changes
resource "aws_cloudwatch_event_rule" "idp_change" {
  name        = "identity-provider-modifications"
  description = "Alert on identity provider configuration changes"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "CreateSAMLProvider",
        "UpdateSAMLProvider",
        "DeleteSAMLProvider",
        "CreateOpenIDConnectProvider",
        "UpdateOpenIDConnectProviderThumbprint",
        "AddClientIDToOpenIDConnectProvider",
        "DeleteOpenIDConnectProvider"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.idp_change.name
target_id = "SendToSNS"
  arn  = aws_sns_topic.idp_change_alerts.arn

  retry_policy {
    maximum_retry_attempts = 8
    maximum_event_age_in_seconds      = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.event_dlq.arn
  }
  input_transformer {
    input_paths = {
      account       = "$.account"
      region        = "$.region"
      time          = "$.time"
      eventName     = "$.detail.eventName"
      eventSource   = "$.detail.eventSource"
      sourceIP      = "$.detail.sourceIPAddress"
      userIdentity  = "$.detail.userIdentity.arn"
    }

    input_template = <<-EOT
"CloudTrail Security Alert
Time: <time>
Account: <account>
Region: <region>
Event: <eventName>
Source: <eventSource>
User: <userIdentity>
Source IP: <sourceIP>
Action: Review CloudTrail event and investigate"
EOT
  }

}

# Step 3: Topic policy
resource "aws_sns_topic_policy" "allow_events" {
  arn = aws_sns_topic.idp_change_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.idp_change_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.idp_change.arn
          }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Identity Provider Configuration Modified",
                alert_description_template=(
                    "Identity provider modified: {eventName} on {providerArn} by {actor}. "
                    "This could enable authentication bypass via federation."
                ),
                investigation_steps=[
                    "Review the specific IdP changes made",
                    "Verify if the modification was authorised",
                    "Check SAML metadata or OIDC thumbprint changes",
                    "Identify who made the change (userIdentity)",
                    "Review trust relationships using this IdP",
                    "Check for new client IDs added to OIDC providers",
                    "Verify certificate thumbprints are from trusted sources",
                    "Look for other authentication-related changes",
                ],
                containment_actions=[
                    "Revert unauthorised IdP configuration changes",
                    "Validate SAML metadata against known good version",
                    "Remove suspicious client IDs from OIDC providers",
                    "Review and update role trust policies using the IdP",
                    "Disable the IdP if compromise is suspected",
                    "Enable AWS CloudTrail data events for IAM",
                    "Implement change control for IdP modifications",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="IdP changes should be rare and well-documented; all events warrant investigation",
            detection_coverage="100% - catches all identity provider API modifications",
            evasion_considerations="Very difficult to evade; requires IAM API calls to modify federation",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "IAM events logged"],
        ),
        # Strategy 4: GCP IAM Conditional Access Policy Changes
        DetectionStrategy(
            strategy_id="t1556-gcp-conditional-access",
            name="GCP IAM Conditional Policy Modifications",
            description="Detect changes to IAM conditional access policies that may weaken authentication controls.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"SetIamPolicy|UpdateIamPolicy"
(protoPayload.request.policy.bindings.condition IS NOT NULL
OR protoPayload.serviceData.policyDelta.bindingDeltas.condition IS NOT NULL)
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect IAM conditional access policy changes

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s1" {
  project      = var.project_id
  display_name = "IAM Conditional Policy Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for conditional policy changes
resource "google_logging_metric" "conditional_policy_changes" {
  project = var.project_id
  name   = "iam-conditional-policy-modifications"
  filter = <<-EOT
    protoPayload.methodName=~"SetIamPolicy|UpdateIamPolicy"
    (protoPayload.request.policy.bindings.condition:*
    OR protoPayload.serviceData.policyDelta.bindingDeltas.condition:*)
    severity="NOTICE"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for conditional access changes
resource "google_monitoring_alert_policy" "conditional_policy" {
  project      = var.project_id
  display_name = "IAM Conditional Access Policy Modified"
  combiner     = "OR"

  conditions {
    display_name = "Conditional policy change detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.conditional_policy_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s1.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = "IAM conditional access policy was modified. This may indicate authentication bypass attempt. Verify changes were authorised."
  }
}""",
                alert_severity="high",
                alert_title="GCP: IAM Conditional Access Policy Modified",
                alert_description_template=(
                    "IAM conditional policy modified in {resourceName}. "
                    "Method: {methodName}. Actor: {principalEmail}."
                ),
                investigation_steps=[
                    "Review the specific policy condition changes",
                    "Check if IP address restrictions were removed",
                    "Verify if time-based access controls were weakened",
                    "Review who made the change (principalEmail)",
                    "Check if device security requirements were removed",
                    "Verify if geographical restrictions were modified",
                    "Review other IAM policy changes by the same actor",
                    "Check for patterns of authentication weakening",
                ],
                containment_actions=[
                    "Revert unauthorised conditional policy changes",
                    "Re-enable IP address and geographic restrictions",
                    "Restore time-based access controls",
                    "Review IAM permissions for policy modification",
                    "Enable organisation policy constraints",
                    "Audit recent authentication events",
                    "Implement change approval for IAM policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known administrators during planned policy updates; require change tickets",
            detection_coverage="90% - catches IAM policy modifications with conditions",
            evasion_considerations="Attackers may remove conditions gradually; monitor policy content semantics",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled", "Admin Activity logs enabled"],
        ),
        # Strategy 5: GCP Identity Provider and Federation Changes
        DetectionStrategy(
            strategy_id="t1556-gcp-federation-modify",
            name="GCP Workforce Identity Federation Modifications",
            description="Detect changes to workforce identity federation and SAML/OIDC providers in GCP.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="iam.googleapis.com"
protoPayload.methodName=~"google.iam.admin.v1.CreateWorkloadIdentityPoolProvider|UpdateWorkloadIdentityPoolProvider|DeleteWorkloadIdentityPoolProvider|CreateWorkforcePoolProvider|UpdateWorkforcePoolProvider|DeleteWorkforcePoolProvider"''',
                gcp_terraform_template="""# GCP: Detect workforce identity federation changes

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email_s2" {
  project      = var.project_id
  display_name = "Federation Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for federation changes
resource "google_logging_metric" "federation_changes" {
  project = var.project_id
  name   = "identity-federation-modifications"
  filter = <<-EOT
    protoPayload.serviceName="iam.googleapis.com"
    protoPayload.methodName=~"CreateWorkloadIdentityPoolProvider|UpdateWorkloadIdentityPoolProvider|DeleteWorkloadIdentityPoolProvider|CreateWorkforcePoolProvider|UpdateWorkforcePoolProvider|DeleteWorkforcePoolProvider"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for federation changes
resource "google_monitoring_alert_policy" "federation_alert" {
  project      = var.project_id
  display_name = "Identity Federation Configuration Modified"
  combiner     = "OR"

  conditions {
    display_name = "Federation provider change detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.federation_changes.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email_s2.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content = "Workforce identity federation provider was created, modified, or deleted. This could enable authentication bypass. Immediate investigation required."
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Identity Federation Provider Modified",
                alert_description_template=(
                    "Federation provider modified: {methodName} for {resourceName}. "
                    "Actor: {principalEmail}. This may enable authentication bypass."
                ),
                investigation_steps=[
                    "Review the specific federation provider changes",
                    "Verify if the modification was authorised",
                    "Check OIDC/SAML configuration changes",
                    "Review attribute mappings for suspicious modifications",
                    "Identify who made the change (principalEmail)",
                    "Check for new identity providers added",
                    "Verify issuer URLs and audience configurations",
                    "Review IAM bindings using the federation provider",
                ],
                containment_actions=[
                    "Revert unauthorised federation provider changes",
                    "Disable suspicious identity providers",
                    "Validate OIDC issuer and audience configurations",
                    "Review attribute condition mappings",
                    "Audit service account impersonation permissions",
                    "Enable organisation policy for federation",
                    "Implement approval workflow for federation changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Federation changes should be rare and well-documented; investigate all events",
            detection_coverage="100% - catches all federation provider API modifications",
            evasion_considerations="Very difficult to evade; requires authenticated API calls to modify federation",
            implementation_effort=EffortLevel.LOW,
            implementation_time="45 minutes",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled", "Admin Activity logs enabled"],
        ),
        # Strategy 6: AWS Cognito Authentication Configuration Changes
        DetectionStrategy(
            strategy_id="t1556-aws-cognito-auth-flow",
            name="Cognito Authentication Flow Modifications",
            description="Detect changes to Cognito user pool authentication flows that may weaken security.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.userPoolId, requestParameters
| filter eventSource = "cognito-idp.amazonaws.com"
| filter eventName in ["UpdateUserPool", "SetUserPoolMfaConfig", "UpdateUserPoolClient", "CreateUserPoolClient"]
| sort @timestamp desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor Cognito authentication configuration changes

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

  # Step 2: Metric filter for Cognito auth changes
  CognitoAuthFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "cognito-idp.amazonaws.com" && ($.eventName = "UpdateUserPool" || $.eventName = "SetUserPoolMfaConfig" || $.eventName = "UpdateUserPoolClient" || $.eventName = "CreateUserPoolClient") }'
      MetricTransformations:
        - MetricName: CognitoAuthChanges
          MetricNamespace: Security/T1556
          MetricValue: "1"

  # Step 3: Alarm for Cognito auth changes
  CognitoAuthAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1556-CognitoAuthConfigChanges
      AlarmDescription: Alert on Cognito authentication configuration changes
      MetricName: CognitoAuthChanges
      Namespace: Security/T1556
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 0
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching

      AlarmActions:
        - !Ref AlertTopic""",
                terraform_template="""# Monitor Cognito authentication configuration changes

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "cognito_auth_alerts" {
  name = "cognito-auth-config-changes"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.cognito_auth_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for Cognito auth changes
resource "aws_cloudwatch_log_metric_filter" "cognito_auth" {
  name           = "cognito-auth-config-changes"
  log_group_name = var.cloudtrail_log_group

  pattern = "{ $.eventSource = \"cognito-idp.amazonaws.com\" && ($.eventName = \"UpdateUserPool\" || $.eventName = \"SetUserPoolMfaConfig\" || $.eventName = \"UpdateUserPoolClient\" || $.eventName = \"CreateUserPoolClient\") }"

  metric_transformation {
    name      = "CognitoAuthChanges"
    namespace = "Security/T1556"
    value     = "1"
  }
}

# Step 3: Alarm for Cognito auth changes
resource "aws_cloudwatch_metric_alarm" "cognito_auth" {
  alarm_name          = "cognito-auth-config-changes"
  metric_name         = "CognitoAuthChanges"
  namespace           = "Security/T1556"
  statistic           = "Sum"
  period              = 300
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions       = [aws_sns_topic.cognito_auth_alerts.arn]
  alarm_description   = "Cognito authentication configuration modified"
}""",
                alert_severity="high",
                alert_title="Cognito Authentication Configuration Changed",
                alert_description_template=(
                    "Cognito authentication modified: {eventName} for user pool {userPoolId}. "
                    "Actor: {actor}. Verify configuration changes were authorised."
                ),
                investigation_steps=[
                    "Review specific authentication flow changes",
                    "Check if MFA enforcement was weakened or disabled",
                    "Verify if password policies were weakened",
                    "Review advanced security features changes",
                    "Check if SRP authentication was disabled",
                    "Verify token validity period modifications",
                    "Review OAuth flow changes in user pool clients",
                    "Check for suspicious callback URLs added",
                ],
                containment_actions=[
                    "Revert unauthorised user pool configuration changes",
                    "Re-enable MFA enforcement if disabled",
                    "Restore secure authentication flows",
                    "Remove suspicious OAuth callback URLs",
                    "Review user pool client configurations",
                    "Enable advanced security features",
                    "Audit IAM permissions for Cognito modifications",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known application deployment processes; require change tickets for user pool modifications",
            detection_coverage="95% - catches Cognito authentication configuration changes",
            evasion_considerations="Attackers may use legitimate administrative credentials; focus on configuration content analysis",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail enabled", "Cognito events logged to CloudWatch"],
        ),
        # Azure Strategy: Modify Authentication Process
        DetectionStrategy(
            strategy_id="t1556-azure",
            name="Azure Modify Authentication Process Detection",
            description=(
                "Azure detection for Modify Authentication Process. "
                "Provides native Azure detection using Log Analytics and Defender for Cloud."
            ),
            detection_type=DetectionType.DEFENDER_ALERT,
            aws_service="n/a",
            azure_service="defender",
            cloud_provider=CloudProvider.AZURE,
            implementation=DetectionImplementation(
                defender_alert_types=["Suspicious activity detected"],
                azure_terraform_template="""# Microsoft Defender for Cloud Detection
# Modify Authentication Process (T1556)
# Microsoft Defender detects Modify Authentication Process activity

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
  name                = "defender-t1556-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "DefAlerts"

  email_receiver {
    name          = "security-team"
    email_address = var.alert_email
  }
}

# Log Analytics query for Defender alerts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "defender_detection" {
  name                = "defender-t1556"
  resource_group_name = var.resource_group_name
  location            = "uksouth"

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

  description = "Microsoft Defender detects Modify Authentication Process activity"
  display_name = "Defender: Modify Authentication Process"
  enabled      = true
}

output "alert_rule_id" {
  value = azurerm_monitor_scheduled_query_rules_alert_v2.defender_detection.id
}""",
                alert_severity="high",
                alert_title="Azure: Modify Authentication Process Detected",
                alert_description_template=(
                    "Modify Authentication Process activity detected. "
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
        "t1556-aws-iam-auth-policy",
        "t1556-gcp-federation-modify",
        "t1556-aws-idp-modify",
        "t1556-gcp-conditional-access",
        "t1556-aws-assume-role-no-mfa",
        "t1556-aws-cognito-auth-flow",
    ],
    total_effort_hours=5.0,
    coverage_improvement="+22% improvement for Credential Access, Persistence, and Defence Evasion tactics",
)
