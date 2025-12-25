"""
T1087 - Account Discovery

Adversaries enumerate valid usernames, accounts, or email addresses to identify
targets for brute-forcing, spear-phishing, and account takeovers across local,
domain, email, and cloud environments.
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
    technique_id="T1087",
    technique_name="Account Discovery",
    tactic_ids=["TA0007"],
    mitre_url="https://attack.mitre.org/techniques/T1087/",
    threat_context=ThreatContext(
        description=(
            "Adversaries pursue account enumeration to identify valid usernames, accounts, "
            "or email addresses within target systems or compromised environments. This "
            "reconnaissance enables downstream attacks including credential brute-forcing, "
            "spear-phishing, and account takeovers. Attackers leverage built-in tools, "
            "command-line utilities, and configuration weaknesses to extract account information "
            "from local systems, domains, email services, and cloud platforms."
        ),
        attacker_goal="Enumerate valid accounts to enable credential attacks and privilege escalation",
        why_technique=[
            "Identifies valid usernames for brute-force attacks",
            "Reveals privileged and administrator accounts",
            "Enables targeted spear-phishing campaigns",
            "Maps organisational hierarchy and roles",
            "Discovers service accounts and API credentials",
            "Identifies inactive or orphaned accounts for takeover",
            "Essential for credential stuffing attacks",
        ],
        known_threat_actors=[],
        recent_campaigns=[],  # Populated dynamically from MITRE sync data
        prevalence="very_common",
        trend="increasing",
        severity_score=5,
        severity_reasoning=(
            "Account discovery is critical reconnaissance that directly enables credential-based "
            "attacks. While discovery itself has minimal impact, it represents active adversary "
            "presence and typically precedes more damaging actions like privilege escalation, "
            "lateral movement, or account takeover. Early detection provides important "
            "opportunity to disrupt attack chains."
        ),
        business_impact=[
            "Indicates active reconnaissance phase",
            "Precursor to credential attacks and account compromise",
            "Reveals high-value targets to adversaries",
            "Enables targeted social engineering",
            "Early warning opportunity to prevent escalation",
        ],
        typical_attack_phase="discovery",
        often_precedes=["T1110", "T1078", "T1098", "T1136", "T1566"],
        often_follows=["T1078.004", "T1190", "T1133", "T1566"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - IAM User/Role Enumeration
        DetectionStrategy(
            strategy_id="t1087-aws-iamenum",
            name="AWS IAM Account Enumeration Detection",
            description="Detect bulk IAM list operations that enumerate users, roles, and groups.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, sourceIPAddress
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["ListUsers", "ListRoles", "ListGroups", "GetUser", "GetRole", "ListAccountAliases"]
| stats count(*) as enum_count by userIdentity.arn, sourceIPAddress, bin(1h)
| filter enum_count > 15
| sort enum_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect IAM account enumeration

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

  # Step 2: Metric filter for IAM account enumeration
  IAMEnumFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "iam.amazonaws.com" && ($.eventName = "ListUsers" || $.eventName = "ListRoles" || $.eventName = "ListGroups" || $.eventName = "GetUser") }'
      MetricTransformations:
        - MetricName: IAMAccountEnumeration
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: CloudWatch alarm for excessive enumeration
  IAMEnumAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: IAMAccountEnumeration
      MetricName: IAMAccountEnumeration
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 25
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect IAM account enumeration

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "iam-account-enum-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for IAM account enumeration
resource "aws_cloudwatch_log_metric_filter" "iam_enum" {
  name           = "iam-account-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"iam.amazonaws.com\" && ($.eventName = \"ListUsers\" || $.eventName = \"ListRoles\" || $.eventName = \"ListGroups\" || $.eventName = \"GetUser\") }"

  metric_transformation {
    name      = "IAMAccountEnumeration"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: CloudWatch alarm for excessive enumeration
resource "aws_cloudwatch_metric_alarm" "iam_enum" {
  alarm_name          = "IAMAccountEnumeration"
  metric_name         = "IAMAccountEnumeration"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 25
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="IAM Account Enumeration Detected",
                alert_description_template="High volume of IAM account list operations from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify the principal performing account enumeration",
                    "Check if this is normal behaviour for the user or role",
                    "Review what account information was accessed",
                    "Look for follow-on credential attacks or privilege escalation",
                    "Check source IP address and location",
                    "Review user's recent authentication history",
                ],
                containment_actions=[
                    "Review principal's IAM permissions",
                    "Check for unauthorised access or credential compromise",
                    "Monitor for brute-force or credential stuffing attempts",
                    "Consider restricting IAM read permissions",
                    "Enable MFA if not already configured",
                    "Rotate credentials if compromise suspected",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist security scanning tools, CSPM solutions, and infrastructure automation",
            detection_coverage="75% - volume-based detection catches bulk enumeration",
            evasion_considerations="Slow enumeration below threshold may evade; using multiple identities spreads load",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        # Strategy 2: AWS - GetAccountAuthorizationDetails
        DetectionStrategy(
            strategy_id="t1087-aws-authdetails",
            name="AWS Complete Account Enumeration Detection",
            description="Detect GetAccountAuthorizationDetails which reveals all IAM users, roles, groups, and policies.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.iam"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {"eventName": ["GetAccountAuthorizationDetails"]},
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect complete IAM account enumeration

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

  # Step 2: EventBridge rule for GetAccountAuthorizationDetails
  AuthDetailsRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.iam]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName: [GetAccountAuthorizationDetails]
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

  # Step 3: SNS topic policy to allow EventBridge
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
                terraform_template="""# Detect complete IAM account enumeration

variable "alert_email" {
  type = string
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "iam-full-enum-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule for GetAccountAuthorizationDetails
resource "aws_cloudwatch_event_rule" "auth_details" {
  name = "complete-iam-enumeration"
  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["GetAccountAuthorizationDetails"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.auth_details.name
  arn  = aws_sns_topic.alerts.arn
}

# Step 3: SNS topic policy to allow EventBridge
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
                alert_title="Complete IAM Account Enumeration Attempted",
                alert_description_template="GetAccountAuthorizationDetails called - complete IAM account dump by {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who called this highly sensitive API",
                    "This API reveals all IAM users, roles, groups, and attached policies",
                    "Check if caller is authorised security tool or administrator",
                    "Review caller's recent activity for other suspicious actions",
                    "Check for follow-on privilege escalation or credential attacks",
                    "Verify source IP address and location",
                ],
                containment_actions=[
                    "Review caller's IAM permissions and legitimacy",
                    "Check for data exfiltration attempts",
                    "Monitor for privilege escalation or account manipulation",
                    "Consider restricting IAM read access",
                    "Rotate credentials if unauthorised access confirmed",
                    "Enable CloudTrail data event logging",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised security tools and compliance scanners using this API",
            detection_coverage="95% - catches all calls to this comprehensive enumeration API",
            evasion_considerations="Cannot evade this detection; adversary may use alternative enumeration methods",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: AWS - EC2 Instance Profile Enumeration
        DetectionStrategy(
            strategy_id="t1087-aws-instanceprofile",
            name="AWS Instance Profile Enumeration Detection",
            description="Detect enumeration of EC2 instance profiles and associated IAM roles.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, eventName, userIdentity.arn, requestParameters.instanceProfileName
| filter eventSource = "iam.amazonaws.com"
| filter eventName in ["ListInstanceProfiles", "GetInstanceProfile", "ListInstanceProfilesForRole"]
| stats count(*) as query_count by userIdentity.arn, bin(1h)
| filter query_count > 10
| sort query_count desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect instance profile account enumeration

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

  # Step 2: Metric filter for instance profile enumeration
  InstanceProfileFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventSource = "iam.amazonaws.com" && ($.eventName = "ListInstanceProfiles" || $.eventName = "GetInstanceProfile") }'
      MetricTransformations:
        - MetricName: InstanceProfileEnumeration
          MetricNamespace: Security
          MetricValue: "1"

  # Step 3: Alarm for excessive queries
  InstanceProfileAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: InstanceProfileEnumeration
      MetricName: InstanceProfileEnumeration
      Namespace: Security
      Statistic: Sum
      Period: 300
      Threshold: 15
      ComparisonOperator: GreaterThanThreshold
      EvaluationPeriods: 1
      TreatMissingData: notBreaching

      AlarmActions: [!Ref AlertTopic]""",
                terraform_template="""# Detect instance profile account enumeration

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "instance-profile-enum-alerts"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Metric filter for instance profile enumeration
resource "aws_cloudwatch_log_metric_filter" "instance_profile" {
  name           = "instance-profile-enumeration"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"iam.amazonaws.com\" && ($.eventName = \"ListInstanceProfiles\" || $.eventName = \"GetInstanceProfile\") }"

  metric_transformation {
    name      = "InstanceProfileEnumeration"
    namespace = "Security"
    value     = "1"
  }
}

# Step 3: Alarm for excessive queries
resource "aws_cloudwatch_metric_alarm" "instance_profile" {
  alarm_name          = "InstanceProfileEnumeration"
  metric_name         = "InstanceProfileEnumeration"
  namespace           = "Security"
  statistic           = "Sum"
  period              = 300
  threshold           = 15
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  treat_missing_data  = "notBreaching"

  alarm_actions [aws_sns_topic.alerts.arn]
}""",
                alert_severity="medium",
                alert_title="Instance Profile Enumeration Detected",
                alert_description_template="Bulk enumeration of EC2 instance profiles from {userIdentity.arn}.",
                investigation_steps=[
                    "Identify who is enumerating instance profiles",
                    "Check if this is authorised infrastructure scanning",
                    "Review what instance profiles were accessed",
                    "Look for attempts to use discovered roles",
                    "Check for EC2 instance compromise indicators",
                ],
                containment_actions=[
                    "Review principal's permissions",
                    "Monitor for instance profile assumption attempts",
                    "Check EC2 instances for compromise",
                    "Audit instance profile role permissions",
                    "Consider least privilege adjustments",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist infrastructure automation and deployment tools",
            detection_coverage="70% - volume-based detection of bulk queries",
            evasion_considerations="Slow enumeration or targeted queries may evade threshold",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="45 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudTrail logging to CloudWatch"],
        ),
        # Strategy 4: GCP - IAM Account Enumeration
        DetectionStrategy(
            strategy_id="t1087-gcp-iamenum",
            name="GCP IAM Account Enumeration Detection",
            description="Detect enumeration of GCP IAM policies, service accounts, and user bindings.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"(GetIamPolicy|ListServiceAccounts|testIamPermissions|iam.serviceAccounts.list|iam.serviceAccounts.get)"''',
                gcp_terraform_template="""# GCP: Detect IAM account enumeration

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

# Step 2: Log-based metric for IAM account enumeration
resource "google_logging_metric" "iam_account_enum" {
  name   = "iam-account-enumeration"
  filter = <<-EOT
    protoPayload.methodName=~"(GetIamPolicy|ListServiceAccounts|testIamPermissions|iam.serviceAccounts.list|iam.serviceAccounts.get)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy for excessive enumeration
resource "google_monitoring_alert_policy" "iam_account_enum" {
  display_name = "IAM Account Enumeration Detected"
  combiner     = "OR"

  conditions {
    display_name = "High volume IAM account queries"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.iam_account_enum.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 50
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: IAM Account Enumeration Detected",
                alert_description_template="High volume of IAM account enumeration queries detected.",
                investigation_steps=[
                    "Identify the principal performing account enumeration",
                    "Check if this is authorised security scanning or CSPM",
                    "Review what IAM account data was accessed",
                    "Look for follow-on privilege escalation attempts",
                    "Verify source IP and authentication context",
                    "Check for service account key creation",
                ],
                containment_actions=[
                    "Review principal's IAM permissions",
                    "Monitor for credential attacks or role manipulation",
                    "Check for unauthorised service account usage",
                    "Consider IAM Conditions to restrict enumeration",
                    "Audit service account key creation and usage",
                    "Enable advanced threat protection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist security tools, CSPM, and infrastructure automation",
            detection_coverage="75% - volume-based detection catches bulk enumeration",
            evasion_considerations="Slow enumeration or use of multiple identities may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
        # Strategy 5: GCP - Workspace User Enumeration
        DetectionStrategy(
            strategy_id="t1087-gcp-workspace",
            name="GCP Workspace User Enumeration Detection",
            description="Detect enumeration of Google Workspace users and groups via Admin SDK.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="admin.googleapis.com"
protoPayload.methodName=~"(admin.directory.users.list|admin.directory.groups.list|admin.directory.users.get)"''',
                gcp_terraform_template="""# GCP: Detect Google Workspace account enumeration

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

# Step 2: Log-based metric for Workspace user enumeration
resource "google_logging_metric" "workspace_enum" {
  name   = "workspace-account-enumeration"
  filter = <<-EOT
    protoPayload.serviceName="admin.googleapis.com"
    protoPayload.methodName=~"(admin.directory.users.list|admin.directory.groups.list|admin.directory.users.get)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "workspace_enum" {
  display_name = "Workspace Account Enumeration"
  combiner     = "OR"

  conditions {
    display_name = "Bulk user/group enumeration"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.workspace_enum.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Workspace Account Enumeration Detected",
                alert_description_template="Bulk enumeration of Google Workspace users and groups detected.",
                investigation_steps=[
                    "Identify who is enumerating Workspace accounts",
                    "Verify if this is authorised HR or admin activity",
                    "Review what user/group information was accessed",
                    "Check for follow-on spear-phishing or social engineering",
                    "Look for unauthorised application access",
                    "Review OAuth token grants",
                ],
                containment_actions=[
                    "Review principal's Admin SDK permissions",
                    "Monitor for targeted phishing attacks",
                    "Check for credential compromise indicators",
                    "Audit third-party application access",
                    "Consider restricting directory read permissions",
                    "Enable advanced phishing and malware protection",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist HR systems, directory sync tools, and admin consoles",
            detection_coverage="80% - catches bulk directory enumeration",
            evasion_considerations="Gradual enumeration or use of legitimate admin tools may evade",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$10-15",
            prerequisites=["Google Workspace Admin SDK audit logs enabled"],
        ),
        # Strategy 6: GCP - Permission Testing for Account Discovery
        DetectionStrategy(
            strategy_id="t1087-gcp-testperm",
            name="GCP Permission Testing Detection",
            description="Detect testIamPermissions used to discover accessible accounts and resources.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.methodName=~"testIamPermissions"''',
                gcp_terraform_template="""# GCP: Detect permission testing for account discovery

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

# Step 2: Log-based metric for permission testing
resource "google_logging_metric" "test_permissions" {
  name   = "iam-permission-testing"
  filter = <<-EOT
    protoPayload.methodName=~"testIamPermissions"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "test_permissions" {
  display_name = "IAM Permission Testing for Account Discovery"
  combiner     = "OR"

  conditions {
    display_name = "Bulk permission testing detected"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.test_permissions.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 100
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Permission Testing for Account Discovery",
                alert_description_template="Bulk testIamPermissions calls indicating account discovery activity.",
                investigation_steps=[
                    "Identify who is performing permission testing",
                    "Review which resources and accounts were tested",
                    "Check for patterns indicating privilege escalation reconnaissance",
                    "Verify if security tool or authorised activity",
                    "Look for follow-on resource access attempts",
                    "Review authentication context and source location",
                ],
                containment_actions=[
                    "Review the principal's activity and permissions",
                    "Monitor for resource access using discovered permissions",
                    "Check for privilege escalation attempts",
                    "Consider restricting testIamPermissions API access",
                    "Audit recent IAM policy changes",
                    "Enable VPC Service Controls if appropriate",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Some applications legitimately test permissions before operations",
            detection_coverage="80% - catches bulk permission testing activity",
            evasion_considerations="Slow testing or targeted permission checks may evade threshold",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=["Cloud Audit Logs enabled"],
        ),
    ],
    recommended_order=[
        "t1087-aws-authdetails",
        "t1087-aws-iamenum",
        "t1087-aws-instanceprofile",
        "t1087-gcp-iamenum",
        "t1087-gcp-workspace",
        "t1087-gcp-testperm",
    ],
    total_effort_hours=5.0,
    coverage_improvement="+12% improvement for Discovery tactic",
)
