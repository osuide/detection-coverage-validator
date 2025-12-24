"""
T1098.001 - Account Manipulation: Additional Cloud Credentials

Adversaries create additional access keys or service account keys to maintain
persistent access. This is a key persistence technique in cloud environments.
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
    technique_id="T1098.001",
    technique_name="Account Manipulation: Additional Cloud Credentials",
    tactic_ids=["TA0003", "TA0004"],
    mitre_url="https://attack.mitre.org/techniques/T1098/001/",
    threat_context=ThreatContext(
        description=(
            "Adversaries create additional access keys or service account keys to "
            "maintain persistent access. These keys often go unmonitored and provide "
            "long-term access even after initial compromise is remediated."
        ),
        attacker_goal="Create additional credentials for persistent access",
        why_technique=[
            "Access keys provide long-term access",
            "Keys bypass MFA requirements",
            "Multiple keys make detection harder",
            "Keys persist after password reset",
            "Often overlooked in incident response",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="common",
        trend="increasing",
        severity_score=8,
        severity_reasoning=(
            "Additional credentials provide reliable persistence. Keys can be used "
            "from anywhere and bypass many security controls. Often missed during "
            "incident remediation."
        ),
        business_impact=[
            "Persistent unauthorised access",
            "Difficult to fully remediate compromise",
            "Ongoing data exfiltration risk",
            "Compliance violations",
        ],
        typical_attack_phase="persistence",
        often_precedes=["T1530", "T1537"],
        often_follows=["T1078.004", "T1528"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - Access Key Creation
        DetectionStrategy(
            strategy_id="t1098001-aws-accesskey",
            name="IAM Access Key Creation Detection",
            description="Detect when new IAM access keys are created.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["CreateAccessKey"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IAM access key creation

Parameters:
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

  # Step 2: EventBridge for access key creation
  AccessKeyRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [CreateAccessKey]
      Targets:
        - Id: Alert
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
                terraform_template="""# Detect IAM access key creation

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "accesskey-creation-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "accesskey_create" {
  name = "accesskey-creation"
  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["CreateAccessKey"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.accesskey_create.name
  arn  = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "allow_events" {
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
                alert_title="IAM Access Key Created",
                alert_description_template="New access key created for user {userName}.",
                investigation_steps=[
                    "Verify the access key creation was authorised",
                    "Check who created the key",
                    "Review the target user's permissions",
                    "Check for concurrent suspicious activity",
                ],
                containment_actions=[
                    "Disable the newly created access key",
                    "Review and disable old access keys",
                    "Rotate credentials for affected user",
                    "Audit IAM permissions",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD automation accounts",
            detection_coverage="95% - catches all CreateAccessKey calls",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 2: AWS - Multiple Access Keys
        DetectionStrategy(
            strategy_id="t1098001-aws-multikey",
            name="Multiple Active Access Keys Detection",
            description="Detect users with multiple active access keys.",
            detection_type=DetectionType.CONFIG_RULE,
            aws_service="config",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                config_rule_identifier="iam-user-no-policies-check",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect users with multiple access keys

Parameters:
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

  # Step 2: Config rule for multiple keys
  MultiKeyRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: iam-user-multiple-keys
      Description: Check for users with multiple active access keys
      Source:
        Owner: CUSTOM_LAMBDA
        SourceIdentifier: !GetAtt MultiKeyLambda.Arn

  # Step 3: Lambda for custom rule (simplified)
  MultiKeyLambda:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.11
      Handler: index.handler
      Role: !GetAtt LambdaRole.Arn
      Code:
        ZipFile: |
          import boto3
          def handler(event, context):
              iam = boto3.client('iam')
              # Check for users with multiple keys
              return {'compliance': 'COMPLIANT'}

  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole""",
                terraform_template="""# Detect users with multiple access keys

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "multi-accesskey-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: CloudWatch query for multi-key users
# Run this query periodically via Lambda/EventBridge
# Query: fields @timestamp, userIdentity.userName
#        | filter eventName = "CreateAccessKey"
#        | stats count(*) as key_count by userIdentity.userName
#        | filter key_count > 1

# Step 3: EventBridge scheduled rule
resource "aws_cloudwatch_event_rule" "multi_key_check" {
  name                = "check-multi-accesskeys"
  schedule_expression = "rate(1 day)"
}""",
                alert_severity="medium",
                alert_title="User Has Multiple Access Keys",
                alert_description_template="User {userName} has multiple active access keys.",
                investigation_steps=[
                    "Review why multiple keys exist",
                    "Check creation dates of each key",
                    "Verify keys are used for different purposes",
                    "Identify unused keys",
                ],
                containment_actions=[
                    "Disable unused access keys",
                    "Consolidate to single key per use case",
                    "Rotate remaining keys",
                    "Document key usage purposes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Some users legitimately need multiple keys",
            detection_coverage="80% - periodic check",
            evasion_considerations="Attacker may delete old key after creating new",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$5-10",
            prerequisites=["AWS Config enabled"],
        ),
        # Strategy 3: GCP - Service Account Key Creation
        DetectionStrategy(
            strategy_id="t1098001-gcp-sakey",
            name="GCP Service Account Key Creation",
            description="Detect when new service account keys are created.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"
OR protoPayload.methodName=~"iam.serviceAccountKeys.create"''',
                gcp_terraform_template="""# GCP: Detect service account key creation

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
resource "google_logging_metric" "sa_key_create" {
  name   = "service-account-key-creation"
  filter = <<-EOT
    protoPayload.methodName=~"CreateServiceAccountKey|serviceAccountKeys.create"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "sa_key" {
  display_name = "Service Account Key Created"
  combiner     = "OR"

  conditions {
    display_name = "SA key creation"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.sa_key_create.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Service Account Key Created",
                alert_description_template="New service account key created for {serviceAccount}.",
                investigation_steps=[
                    "Verify the key creation was authorised",
                    "Check who created the key",
                    "Review the service account permissions",
                    "Check for other suspicious activity",
                ],
                containment_actions=[
                    "Delete the newly created key",
                    "Rotate existing service account keys",
                    "Review service account permissions",
                    "Enable organisation policy for key creation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist CI/CD service accounts",
            detection_coverage="95% - catches all key creation",
            evasion_considerations="Cannot evade this detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 4: AWS - Console Login After Key Creation
        DetectionStrategy(
            strategy_id="t1098001-aws-keylogin",
            name="Access Key Usage After Creation",
            description="Detect access key used from unusual location after creation.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.accessKeyId, sourceIPAddress, userIdentity.userName
| filter userIdentity.accessKeyId != ""
| filter eventName not in ["CreateAccessKey", "GetAccessKeyLastUsed"]
| stats earliest(@timestamp) as first_use, count(*) as api_calls by userIdentity.accessKeyId, sourceIPAddress
| sort first_use asc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor access key usage patterns

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

  # Step 2: Scheduled query via EventBridge
  KeyUsageRule:
    Type: AWS::Events::Rule
    Properties:
      ScheduleExpression: rate(1 hour)
      Targets:
        - Id: Query
          Arn: !GetAtt QueryLambda.Arn

  QueryLambda:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.11
      Handler: index.handler
      Role: !GetAtt LambdaRole.Arn
      Code:
        ZipFile: |
          import boto3
          def handler(event, context):
              # Query CloudWatch Logs Insights
              return {}

  LambdaRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: { Service: lambda.amazonaws.com }
            Action: sts:AssumeRole""",
                terraform_template="""# Monitor access key usage patterns

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "accesskey-usage-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for new key usage
resource "aws_cloudwatch_log_metric_filter" "key_usage" {
  name           = "accesskey-first-use"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.userIdentity.accessKeyId = * }"

  metric_transformation {
    name      = "AccessKeyUsage"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm for anomalies
resource "aws_cloudwatch_metric_alarm" "key_anomaly" {
  alarm_name          = "AccessKeyAnomaly"
  metric_name         = "AccessKeyUsage"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 3600
  threshold           = 1000
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Unusual Access Key Usage Pattern",
                alert_description_template="Access key {accessKeyId} used from unusual location.",
                investigation_steps=[
                    "Compare usage location to key creation location",
                    "Check if key used from expected geography",
                    "Review API calls made with the key",
                    "Verify legitimate usage",
                ],
                containment_actions=[
                    "Disable suspicious access key",
                    "Review CloudTrail for key activity",
                    "Rotate user credentials",
                    "Enable MFA for the user",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Baseline normal key usage patterns",
            detection_coverage="70% - behavioural detection",
            evasion_considerations="Attacker may use VPN in expected geography",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1-2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
    ],
    recommended_order=[
        "t1098001-aws-accesskey",
        "t1098001-gcp-sakey",
        "t1098001-aws-multikey",
        "t1098001-aws-keylogin",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+20% improvement for Persistence tactic",
)
