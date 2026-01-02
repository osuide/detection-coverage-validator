"""
T1562.008 - Impair Defences: Disable or Modify Cloud Logs

Adversaries disable or modify cloud logging to evade detection.
Common targets: CloudTrail, Cloud Audit Logs, VPC Flow Logs, S3 Access Logs.
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
    technique_id="T1562.008",
    technique_name="Impair Defences: Disable or Modify Cloud Logs",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1562/008/",
    threat_context=ThreatContext(
        description=(
            "Adversaries disable or modify cloud logging services to evade detection. "
            "Targets include CloudTrail, VPC Flow Logs, Cloud Audit Logs, S3 access logs, "
            "and application-level logging. This is often an early step after gaining access."
        ),
        attacker_goal="Disable cloud logging to hide malicious activity",
        why_technique=[
            "Eliminates audit trail of attacker actions",
            "Makes incident response difficult",
            "Often done early in attack chain",
            "Single API call can disable logging",
            "May go unnoticed without monitoring",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="stable",
        severity_score=9,
        severity_reasoning=(
            "Disabling logging blinds defenders and enables follow-on attacks. "
            "Often indicates active compromise requiring immediate response. "
            "Without logs, incident investigation becomes extremely difficult."
        ),
        business_impact=[
            "Loss of audit trail for compliance",
            "Inability to investigate incidents",
            "Potential regulatory violations",
            "Extended dwell time for attackers",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1530", "T1537", "T1078.004"],
        often_follows=["T1078.004", "T1528"],
    ),
    detection_strategies=[
        # =====================================================================
        # STRATEGY 1: GuardDuty Stealth Detection (Recommended First)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1562008-aws-guardduty",
            name="AWS GuardDuty Stealth Detection",
            description=(
                "Leverage GuardDuty's built-in Stealth finding types to detect logging "
                "tampering. GuardDuty automatically monitors for CloudTrail disable events "
                "and S3 access logging changes. See: "
                "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html"
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    "Stealth:IAMUser/CloudTrailLoggingDisabled",
                    "Stealth:S3/ServerAccessLoggingDisabled",
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  GuardDuty Stealth Detection for Logging Tampering
  Detects: Stealth:IAMUser/CloudTrailLoggingDisabled, Stealth:S3/ServerAccessLoggingDisabled
  See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html

Parameters:
  AlertEmail:
    Type: String
    Description: Email for critical security alerts

Resources:
  # SNS Topic for Stealth findings (high priority)
  StealthAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: guardduty-stealth-alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref StealthAlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # EventBridge rule for Stealth findings
  StealthFindingRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-stealth-findings
      Description: Detect logging tampering via GuardDuty Stealth findings
      State: ENABLED
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "Stealth:"
      Targets:
        - Id: SendToSNS
          Arn: !Ref StealthAlertTopic
          InputTransformer:
            InputPathsMap:
              findingType: $.detail.type
              severity: $.detail.severity
              principal: $.detail.resource.accessKeyDetails.userName
              accountId: $.account
              region: $.detail.region
            InputTemplate: |
              "CRITICAL: GuardDuty Stealth Finding"
              "Type: <findingType>"
              "Severity: <severity>"
              "Principal: <principal>"
              "Account: <accountId>"
              "Region: <region>"
              "Action Required: Immediately investigate logging configuration"

  DeadLetterQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: guardduty-stealth-dlq
      MessageRetentionPeriod: 1209600

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref StealthAlertTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowEventBridgePublishScoped
            Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref StealthAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt StealthFindingRule.Arn

  # Enable GuardDuty if not already enabled
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true

Outputs:
  AlertTopicArn:
    Description: SNS topic for Stealth alerts
    Value: !Ref StealthAlertTopic""",
                terraform_template="""# AWS GuardDuty Stealth Detection for Logging Tampering
# Detects: Stealth:IAMUser/CloudTrailLoggingDisabled, Stealth:S3/ServerAccessLoggingDisabled
# See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html

variable "alert_email" {
  type        = string
  description = "Email for critical security alerts"
}

# Step 1: Create encrypted SNS topic for Stealth alerts
resource "aws_sns_topic" "stealth_alerts" {
  name              = "guardduty-stealth-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "alert_email" {
  topic_arn = aws_sns_topic.stealth_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Enable GuardDuty detector
resource "aws_guardduty_detector" "main" {
  enable = true
}

# Step 3: Route all Stealth findings to SNS
resource "aws_cloudwatch_event_rule" "stealth_findings" {
  name        = "guardduty-stealth-findings"
  description = "Detect logging tampering via GuardDuty Stealth findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "Stealth:" }]
    }
  })
}

data "aws_caller_identity" "current" {}

# Step 4: Dead letter queue
resource "aws_sqs_queue" "dlq" {
  name                      = "guardduty-stealth-dlq"
  message_retention_seconds = 1209600
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

    resources = [aws_sqs_queue.dlq.arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.stealth_findings.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}

# Step 5: EventBridge target with DLQ, retry, input transformer
resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.stealth_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.stealth_alerts.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }

  input_transformer {
    input_paths = {
      findingType = "$.detail.type"
      severity    = "$.detail.severity"
      principal   = "$.detail.resource.accessKeyDetails.userName"
      accountId   = "$.account"
      region      = "$.detail.region"
    }
    input_template = <<-EOF
"CRITICAL: GuardDuty Stealth Finding (T1562.008)
Type: <findingType>
Severity: <severity>
Principal: <principal>
Account: <accountId>
Region: <region>
Action Required: Immediately investigate logging configuration"
EOF
  }
}

# Step 6: Scoped SNS topic policy
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.stealth_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublishScoped"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.stealth_alerts.arn
      Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnEquals = {
          "aws:SourceArn" = aws_cloudwatch_event_rule.stealth_findings.arn
        }
      }
    }]
  })
}""",
                alert_severity="critical",
                alert_title="GuardDuty: Logging Tampering Detected (Stealth Finding)",
                alert_description_template=(
                    "GuardDuty has detected a Stealth finding: {type}. "
                    "This indicates an attempt to disable or modify logging. "
                    "Principal {principal} may have disabled CloudTrail or S3 access logging."
                ),
                investigation_steps=[
                    "Review the specific GuardDuty finding in the console for full context",
                    "Check if CloudTrail is currently enabled across all regions",
                    "Verify S3 bucket access logging configuration",
                    "Identify all actions taken by the principal before and after this event",
                    "Check for concurrent suspicious activity that may now be unlogged",
                ],
                containment_actions=[
                    "Immediately re-enable CloudTrail logging in all regions",
                    "Re-enable S3 access logging on affected buckets",
                    "Rotate credentials for the principal that made the change",
                    "Apply a restrictive inline policy to the principal",
                    "Enable CloudTrail log file integrity validation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "GuardDuty Stealth findings have very low false positives. "
                "Legitimate logging changes should be rare and well-documented. "
                "Archive findings only for pre-approved infrastructure changes."
            ),
            detection_coverage="95% - GuardDuty monitors CloudTrail and S3 logging automatically",
            evasion_considerations=(
                "Cannot evade if logs are sent to a separate AWS account. "
                "Multi-region trail to Organisation trail makes evasion harder."
            ),
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost=(
                "$4-5 per million CloudTrail events. "
                "See: https://aws.amazon.com/guardduty/pricing/"
            ),
            prerequisites=["AWS account with CloudTrail enabled (default)"],
        ),
        # =====================================================================
        # STRATEGY 2: AWS Config Compliance Rules
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1562008-aws-config",
            name="AWS Config CloudTrail Compliance Rules",
            description=(
                "Use AWS Config managed rules to continuously monitor CloudTrail "
                "configuration and automatically remediate if logging is disabled. "
                "See: https://docs.aws.amazon.com/config/latest/developerguide/cloudtrail-enabled.html"
            ),
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="config",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                config_rule_identifier="CLOUDTRAIL_ENABLED",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: |
  AWS Config rules for CloudTrail compliance monitoring
  Rules: cloudtrail-enabled, cloud-trail-log-file-validation-enabled
  See: https://docs.aws.amazon.com/config/latest/developerguide/cloudtrail-enabled.html

Parameters:
  AlertEmail:
    Type: String
    Description: Email for compliance alerts

Resources:
  # SNS Topic for Config compliance alerts
  ComplianceAlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      KmsMasterKeyId: alias/aws/sns
      TopicName: config-cloudtrail-compliance
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref ComplianceAlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # Config Rule: CloudTrail Enabled
  CloudTrailEnabledRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: cloudtrail-enabled
      Description: Checks if CloudTrail is enabled in your AWS account
      Source:
        Owner: AWS
        SourceIdentifier: CLOUDTRAIL_ENABLED
      MaximumExecutionFrequency: One_Hour

  # Config Rule: Log File Validation Enabled
  LogFileValidationRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: cloud-trail-log-file-validation-enabled
      Description: Checks if CloudTrail log file validation is enabled
      Source:
        Owner: AWS
        SourceIdentifier: CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED

  # Config Rule: CloudWatch Logs Integration
  CloudWatchLogsRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: cloud-trail-cloud-watch-logs-enabled
      Description: Checks if CloudTrail trails are configured to send logs to CloudWatch
      Source:
        Owner: AWS
        SourceIdentifier: CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED

  # EventBridge rule for compliance changes
  ComplianceChangeRule:
    Type: AWS::Events::Rule
    Properties:
      Name: config-cloudtrail-compliance-change
      Description: Alert on CloudTrail Config rule compliance changes
      State: ENABLED
      EventPattern:
        source:
          - aws.config
        detail-type:
          - Config Rules Compliance Change
        detail:
          configRuleName:
            - cloudtrail-enabled
            - cloud-trail-log-file-validation-enabled
            - cloud-trail-cloud-watch-logs-enabled
          newEvaluationResult:
            complianceType:
              - NON_COMPLIANT
      Targets:
        - Id: SendToSNS
          Arn: !Ref ComplianceAlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref ComplianceAlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref ComplianceAlertTopic
            Condition:
              StringEquals:
                AWS:SourceAccount: !Ref AWS::AccountId
              ArnEquals:
                aws:SourceArn: !GetAtt ComplianceChangeRule.Arn

Outputs:
  CloudTrailEnabledRuleArn:
    Description: ARN of the cloudtrail-enabled Config rule
    Value: !GetAtt CloudTrailEnabledRule.Arn""",
                terraform_template="""# AWS Config CloudTrail Compliance Rules
# Rules: cloudtrail-enabled, cloud-trail-log-file-validation-enabled
# See: https://docs.aws.amazon.com/config/latest/developerguide/cloudtrail-enabled.html

variable "alert_email" {
  type        = string
  description = "Email for compliance alerts"
}

# Step 1: SNS topic for compliance alerts
resource "aws_sns_topic" "compliance_alerts" {
  name              = "config-cloudtrail-compliance"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.compliance_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Config rules for CloudTrail compliance
resource "aws_config_config_rule" "cloudtrail_enabled" {
  name        = "cloudtrail-enabled"
  description = "Checks if CloudTrail is enabled in your AWS account"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDTRAIL_ENABLED"
  }

  maximum_execution_frequency = "One_Hour"

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "log_file_validation" {
  name        = "cloud-trail-log-file-validation-enabled"
  description = "Checks if CloudTrail log file validation is enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloudwatch_logs_enabled" {
  name        = "cloud-trail-cloud-watch-logs-enabled"
  description = "Checks if CloudTrail trails send logs to CloudWatch"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Step 3: EventBridge rule for compliance changes
resource "aws_cloudwatch_event_rule" "compliance_change" {
  name        = "config-cloudtrail-compliance-change"
  description = "Alert on CloudTrail Config rule compliance changes"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = [
        "cloudtrail-enabled",
        "cloud-trail-log-file-validation-enabled",
        "cloud-trail-cloud-watch-logs-enabled"
      ]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "to_sns" {
  rule      = aws_cloudwatch_event_rule.compliance_change.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.compliance_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.compliance_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.compliance_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.compliance_change.arn
          }
      }
    }]
  })
}

# Note: AWS Config recorder must be enabled separately
# This is typically done at the organisation level
resource "aws_config_configuration_recorder" "main" {
  name     = "default"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported = true
  }
}

resource "aws_iam_role" "config_role" {
  name = "config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}""",
                alert_severity="critical",
                alert_title="AWS Config: CloudTrail Compliance Violation",
                alert_description_template=(
                    "AWS Config has detected a CloudTrail compliance violation. "
                    "Rule {configRuleName} is now NON_COMPLIANT. "
                    "CloudTrail logging may be disabled or misconfigured."
                ),
                investigation_steps=[
                    "Check the AWS Config console for the specific compliance violation",
                    "Verify CloudTrail configuration in each region",
                    "Review CloudTrail event history for who made the change",
                    "Check if log file validation is enabled",
                    "Verify logs are being sent to CloudWatch and/or S3",
                ],
                containment_actions=[
                    "Re-enable CloudTrail with proper configuration",
                    "Enable log file integrity validation",
                    "Configure CloudTrail to send logs to CloudWatch",
                    "Set up automatic remediation via AWS Config",
                    "Review IAM policies to restrict CloudTrail modifications",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Config rules evaluate continuously with minimal false positives. "
                "Ensure CloudTrail is properly configured before enabling rules. "
                "Use resource exceptions for intentionally disabled trails in dev accounts."
            ),
            detection_coverage="90% - continuous compliance monitoring",
            evasion_considerations="Config rules detect state, not the act of disabling",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost=(
                "AWS Config: $2 per rule evaluation/month. "
                "With 3 rules: ~$6/month. "
                "See: https://aws.amazon.com/config/pricing/"
            ),
            prerequisites=[
                "AWS Config recorder enabled",
                "CloudTrail enabled for baseline",
            ],
        ),
        # =====================================================================
        # STRATEGY 3: EventBridge Multi-Service Logging Monitor
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1562008-aws-eventbridge",
            name="EventBridge Multi-Service Logging Monitor",
            description=(
                "Comprehensive EventBridge rules to detect modifications to all "
                "AWS logging services: CloudTrail, VPC Flow Logs, S3 access logs, "
                "CloudWatch Logs, and GuardDuty."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": [
                        "aws.cloudtrail",
                        "aws.ec2",
                        "aws.s3",
                        "aws.logs",
                        "aws.guardduty",
                    ],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "StopLogging",
                            "DeleteTrail",
                            "UpdateTrail",
                            "PutEventSelectors",
                            "DeleteFlowLogs",
                            "PutBucketLogging",
                            "DeleteBucketLogging",
                            "DeleteLogGroup",
                            "DeleteLogStream",
                            "PutRetentionPolicy",
                            "DeleteDetector",
                            "UpdateDetector",
                            "DisassociateMembers",
                        ]
                    },
                },
                terraform_template="""# EventBridge Multi-Service Logging Monitor
# Monitors: CloudTrail, VPC Flow Logs, S3 Access Logs, CloudWatch Logs, GuardDuty

variable "alert_email" {
  type        = string
  description = "Email for logging modification alerts"
}

# Step 1: SNS topic for logging alerts
resource "aws_sns_topic" "logging_alerts" {
  name              = "logging-modification-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.logging_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for CloudTrail modifications
resource "aws_cloudwatch_event_rule" "cloudtrail_mod" {
  name        = "cloudtrail-modifications"
  description = "Detect CloudTrail stop, delete, or modify events"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors",
        "RemoveTags"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "cloudtrail_to_sns" {
  rule      = aws_cloudwatch_event_rule.cloudtrail_mod.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.logging_alerts.arn

  input_transformer {
    input_paths = {
      eventName = "$.detail.eventName"
      user      = "$.detail.userIdentity.arn"
      sourceIp  = "$.detail.sourceIPAddress"
      trailArn  = "$.detail.requestParameters.name"
    }
    input_template = <<-EOF
      {
        "alert": "CloudTrail Modification",
        "severity": "CRITICAL",
        "event": "<eventName>",
        "user": "<user>",
        "sourceIp": "<sourceIp>",
        "trail": "<trailArn>",
        "action": "Immediately verify CloudTrail is still logging"
      }
    EOF
  }
}

# Step 3: EventBridge rule for VPC Flow Logs modifications
resource "aws_cloudwatch_event_rule" "flowlogs_mod" {
  name        = "flowlogs-modifications"
  description = "Detect VPC Flow Logs deletion"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["DeleteFlowLogs"]
    }
  })
}

resource "aws_cloudwatch_event_target" "flowlogs_to_sns" {
  rule      = aws_cloudwatch_event_rule.flowlogs_mod.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.logging_alerts.arn

  input_transformer {
    input_paths = {
      user     = "$.detail.userIdentity.arn"
      sourceIp = "$.detail.sourceIPAddress"
      flowLogs = "$.detail.requestParameters.DeleteFlowLogsRequest.FlowLogId"
    }
    input_template = <<-EOF
      {
        "alert": "VPC Flow Logs Deleted",
        "severity": "HIGH",
        "user": "<user>",
        "sourceIp": "<sourceIp>",
        "flowLogIds": "<flowLogs>",
        "action": "Re-enable flow logs on affected VPCs"
      }
    EOF
  }
}

# Step 4: EventBridge rule for S3 access logging modifications
resource "aws_cloudwatch_event_rule" "s3_logging_mod" {
  name        = "s3-logging-modifications"
  description = "Detect S3 access logging changes"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["PutBucketLogging"]
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_to_sns" {
  rule      = aws_cloudwatch_event_rule.s3_logging_mod.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.logging_alerts.arn

  input_transformer {
    input_paths = {
      user     = "$.detail.userIdentity.arn"
      bucket   = "$.detail.requestParameters.bucketName"
      sourceIp = "$.detail.sourceIPAddress"
    }
    input_template = <<-EOF
      {
        "alert": "S3 Access Logging Modified",
        "severity": "HIGH",
        "user": "<user>",
        "bucket": "<bucket>",
        "sourceIp": "<sourceIp>",
        "action": "Verify S3 access logging is still enabled"
      }
    EOF
  }
}

# Step 5: EventBridge rule for CloudWatch Logs modifications
resource "aws_cloudwatch_event_rule" "cwlogs_mod" {
  name        = "cloudwatch-logs-modifications"
  description = "Detect CloudWatch log group/stream deletion"

  event_pattern = jsonencode({
    source      = ["aws.logs"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "DeleteLogGroup",
        "DeleteLogStream",
        "PutRetentionPolicy"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "cwlogs_to_sns" {
  rule      = aws_cloudwatch_event_rule.cwlogs_mod.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.logging_alerts.arn
}

# Step 6: EventBridge rule for GuardDuty modifications
resource "aws_cloudwatch_event_rule" "guardduty_mod" {
  name        = "guardduty-modifications"
  description = "Detect GuardDuty detector disable or delete"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "DeleteDetector",
        "UpdateDetector",
        "DisassociateMembers",
        "StopMonitoringMembers"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_mod.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.logging_alerts.arn

  input_transformer {
    input_paths = {
      eventName = "$.detail.eventName"
      user      = "$.detail.userIdentity.arn"
      sourceIp  = "$.detail.sourceIPAddress"
    }
    input_template = <<-EOF
      {
        "alert": "GuardDuty Configuration Modified",
        "severity": "CRITICAL",
        "event": "<eventName>",
        "user": "<user>",
        "sourceIp": "<sourceIp>",
        "action": "Verify GuardDuty is still enabled and monitoring"
      }
    EOF
  }
}

# SNS topic policy
resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.logging_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgePublish"
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.logging_alerts.arn
    Condition = {
        StringEquals = {
          "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
        }
          ArnEquals = {
            "aws:SourceArn" = [
              aws_cloudwatch_event_rule.cloudtrail_mod.arn,
              aws_cloudwatch_event_rule.flowlogs_mod.arn,
              aws_cloudwatch_event_rule.s3_logging_mod.arn,
              aws_cloudwatch_event_rule.cwlogs_mod.arn,
              aws_cloudwatch_event_rule.guardduty_mod.arn,
            ]
          }
      }
    }]
  })
}

output "alert_topic_arn" {
  value       = aws_sns_topic.logging_alerts.arn
  description = "SNS topic for logging modification alerts"
}""",
                alert_severity="critical",
                alert_title="AWS Logging Service Modified",
                alert_description_template=(
                    "A logging service modification was detected: {eventName}. "
                    "User {userIdentity.arn} modified logging from {sourceIPAddress}."
                ),
                investigation_steps=[
                    "Identify which logging service was modified",
                    "Check if logging is currently enabled for the affected service",
                    "Review the user's recent activity for other suspicious actions",
                    "Verify the source IP is from a known location",
                    "Check for any data exfiltration that may have occurred during the gap",
                ],
                containment_actions=[
                    "Re-enable the affected logging service immediately",
                    "Rotate credentials for the user who made the change",
                    "Apply SCPs to prevent logging modifications",
                    "Enable Organisation-level logging controls",
                    "Review and restrict IAM permissions for logging APIs",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Add exceptions for authorised infrastructure automation. "
                "Use Lambda to filter expected changes (e.g., log rotation). "
                "Require change approval workflow for logging modifications."
            ),
            detection_coverage="95% - covers all major logging modification APIs",
            evasion_considerations="Cannot evade if CloudTrail itself is still logging the disable attempt",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-10/month (EventBridge + SNS)",
            prerequisites=["CloudTrail enabled for API event logging"],
        ),
        # =====================================================================
        # STRATEGY 4: GCP Audit Log Tampering Detection
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1562008-gcp-auditlogs",
            name="GCP Audit Log Tampering Detection",
            description=(
                "Detect attempts to modify or delete GCP Cloud Audit Logs configuration. "
                "Note: Admin Activity logs cannot be disabled in GCP. "
                "This monitors Data Access logs and log sinks which can be modified."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""# Detect audit log configuration changes
protoPayload.serviceName="logging.googleapis.com"
protoPayload.methodName=~"(UpdateSink|DeleteSink|UpdateBucket|DeleteBucket|SetIamPolicy)"
severity>=WARNING

# Detect Data Access audit config changes
protoPayload.methodName="SetIamPolicy"
protoPayload.request.policy.auditConfigs:*""",
                gcp_terraform_template="""# GCP Audit Log Tampering Detection
# Note: Admin Activity logs CANNOT be disabled in GCP
# This monitors Data Access logs and log sinks

variable "project_id" {
  type        = string
  description = "GCP Project ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Audit Log Security Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Log-based metric for log sink modifications
resource "google_logging_metric" "log_sink_changes" {
  name    = "log-sink-modifications"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="logging.googleapis.com"
    protoPayload.methodName=~"(UpdateSink|DeleteSink|CreateSink)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "method"
      value_type  = "STRING"
      description = "API method called"
    }
    labels {
      key         = "principal"
      value_type  = "STRING"
      description = "Principal making the change"
    }
  }

  label_extractors = {
    "method"    = "EXTRACT(protoPayload.methodName)"
    "principal" = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
  }
}

# Step 3: Alert on log sink modifications
resource "google_monitoring_alert_policy" "log_sink_alert" {
  project      = var.project_id
  display_name = "CRITICAL: Log Sink Modified or Deleted"
  combiner     = "OR"

  conditions {
    display_name = "Log sink configuration changed"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.log_sink_changes.name}\" resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "A log sink was modified or deleted. This may indicate an attempt to disable logging. Immediately verify log export configuration."
    mime_type = "text/markdown"
  }
}

# Step 4: Log-based metric for Data Access audit config changes
resource "google_logging_metric" "data_access_config" {
  name    = "data-access-audit-config-changes"
  project = var.project_id

  filter = <<-EOT
    protoPayload.methodName="SetIamPolicy"
    protoPayload.request.policy.auditConfigs:*
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Step 5: Alert on Data Access audit config changes
resource "google_monitoring_alert_policy" "data_access_alert" {
  project      = var.project_id
  display_name = "Data Access Audit Configuration Changed"
  combiner     = "OR"

  conditions {
    display_name = "Audit config modified"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.data_access_config.name}\" resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "Data Access audit logging configuration was changed. Verify that required services still have audit logging enabled."
    mime_type = "text/markdown"
  }
}

# Step 6: Log-based metric for logging bucket modifications
resource "google_logging_metric" "logging_bucket_changes" {
  name    = "logging-bucket-modifications"
  project = var.project_id

  filter = <<-EOT
    protoPayload.serviceName="logging.googleapis.com"
    protoPayload.methodName=~"(UpdateBucket|DeleteBucket)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "logging_bucket_alert" {
  project      = var.project_id
  display_name = "CRITICAL: Logging Bucket Modified or Deleted"
  combiner     = "OR"

  conditions {
    display_name = "Logging bucket changed"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.logging_bucket_changes.name}\" resource.type=\"global\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "1800s"
    notification_rate_limit {
      period = "300s"
    }
  }

  documentation {
    content   = "A logging bucket was modified or deleted. This is a critical security event. Immediately investigate and restore logging configuration."
    mime_type = "text/markdown"
  }
}

output "notification_channel_id" {
  value       = google_monitoring_notification_channel.email.id
  description = "Notification channel for alerts"
}""",
                alert_severity="critical",
                alert_title="GCP: Audit Log Configuration Modified",
                alert_description_template=(
                    "Cloud Audit Logs configuration was modified by {principal}. "
                    "Method: {method}. This may indicate an attempt to disable logging."
                ),
                investigation_steps=[
                    "Review what logging configuration changed in the activity log",
                    "Identify the principal making the change",
                    "Check if log sinks were deleted or modified",
                    "Verify current logging coverage for all critical services",
                    "Check if Data Access logs were disabled for any service",
                ],
                containment_actions=[
                    "Restore deleted or modified log sinks",
                    "Re-enable Data Access logs for affected services",
                    "Lock down logging configuration with Organisation Policies",
                    "Review and restrict IAM permissions for logging.admin role",
                    "Export logs to an immutable destination (e.g., locked bucket)",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "Log sink and bucket changes are rare in production. "
                "Add exceptions for known infrastructure automation. "
                "Use Organisation Policies to prevent log modifications."
            ),
            detection_coverage="90% - monitors all log configuration APIs",
            evasion_considerations=(
                "Admin Activity logs cannot be disabled in GCP. "
                "Attacker can only disable Data Access logs or delete sinks."
            ),
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost=(
                "Cloud Logging: Free tier covers 50GB/month. "
                "Monitoring: Free for first 100 alert policies. "
                "Typical cost: $10-20/month."
            ),
            prerequisites=[
                "Cloud Audit Logs enabled (Admin Activity is always on)",
                "Data Access logs enabled for sensitive services",
            ],
        ),
        # =====================================================================
        # STRATEGY 5: Organisation-Level Log Protection (Enterprise)
        # =====================================================================
        DetectionStrategy(
            strategy_id="t1562008-aws-org-protection",
            name="AWS Organisation Log Protection",
            description=(
                "Enterprise-grade protection using AWS Organisations SCPs and "
                "centralised logging to prevent member accounts from disabling logging."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="organizations",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                terraform_template="""# AWS Organisation Log Protection
# Enterprise-grade: SCP + Centralised Logging + Member Account Monitoring

variable "org_id" {
  type        = string
  description = "AWS Organisation ID"
}

variable "security_account_id" {
  type        = string
  description = "Centralised security/logging account ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SCP to deny logging modifications (attach to OUs)
resource "aws_organizations_policy" "deny_logging_disable" {
  name        = "DenyLoggingDisable"
  description = "Prevent disabling CloudTrail, GuardDuty, and other logging services"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyCloudTrailDisable"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "cloudtrail:UpdateTrail"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = var.org_id
          }
        }
      },
      {
        Sid    = "DenyGuardDutyDisable"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "guardduty:UpdateDetector",
          "guardduty:DisassociateMembers"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyFlowLogsDelete"
        Effect = "Deny"
        Action = [
          "ec2:DeleteFlowLogs"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyConfigDisable"
        Effect = "Deny"
        Action = [
          "config:StopConfigurationRecorder",
          "config:DeleteConfigurationRecorder"
        ]
        Resource = "*"
      }
    ]
  })
}

# Step 2: Organisation CloudTrail (logs to security account)
resource "aws_cloudtrail" "organization_trail" {
  name                          = "organization-trail"
  s3_bucket_name               = aws_s3_bucket.cloudtrail_logs.id
  is_organization_trail        = true
  is_multi_region_trail        = true
  enable_log_file_validation   = true
  include_global_service_events = true
  kms_key_id                   = aws_kms_key.cloudtrail.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }
  }
}

# Step 3: S3 bucket with object lock (immutable logs)
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "org-cloudtrail-logs-$${var.security_account_id}"
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 365
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "$${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "DenyDelete"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource  = "$${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalAccount" = var.security_account_id
          }
        }
      }
    ]
  })
}

# Step 4: KMS key for CloudTrail encryption
resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "Enable IAM User Permissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::$${var.security_account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "Allow CloudTrail to encrypt logs"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
      }
    ]
  })
}

output "organization_trail_arn" {
  value       = aws_cloudtrail.organization_trail.arn
  description = "Organisation CloudTrail ARN"
}

output "scp_policy_id" {
  value       = aws_organizations_policy.deny_logging_disable.id
  description = "SCP policy ID for logging protection"
}""",
                alert_severity="critical",
                alert_title="Organisation-Level Logging Protection",
                alert_description_template=(
                    "This is a preventive control. Organisation SCPs prevent "
                    "member accounts from disabling logging services."
                ),
                investigation_steps=[
                    "This is a preventive control - no investigation needed for prevented actions",
                    "Review SCP deny events in CloudTrail for attempted violations",
                    "Check if any accounts are exempt from SCPs",
                    "Verify Organisation Trail is still logging",
                ],
                containment_actions=[
                    "SCPs automatically prevent logging modifications",
                    "Review and update SCP exceptions if needed",
                    "Ensure all OUs have the SCP attached",
                    "Verify centralised logging bucket is receiving logs",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning=(
                "SCPs prevent actions entirely - no false positives. "
                "Add exception conditions for break-glass scenarios."
            ),
            detection_coverage="99% - preventive control blocks actions before they occur",
            evasion_considerations=(
                "Management account is exempt from SCPs. "
                "Ensure management account has separate monitoring."
            ),
            implementation_effort=EffortLevel.HIGH,
            implementation_time="4-6 hours",
            estimated_monthly_cost=(
                "Organisation Trail: $2/100,000 events. "
                "S3 with Object Lock: $0.023/GB. "
                "KMS: $1/key + $0.03/10,000 requests. "
                "Total: $20-50/month for typical org."
            ),
            prerequisites=[
                "AWS Organisations enabled",
                "Management account access",
                "Centralised security account",
            ],
        ),
    ],
    recommended_order=[
        "t1562008-aws-guardduty",
        "t1562008-aws-config",
        "t1562008-aws-eventbridge",
        "t1562008-gcp-auditlogs",
        "t1562008-aws-org-protection",
    ],
    total_effort_hours=10.0,
    coverage_improvement="+30% improvement for Defence Evasion tactic with multi-layered detection",
)
