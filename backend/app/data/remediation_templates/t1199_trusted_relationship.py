"""
T1199 - Trusted Relationship

Adversaries exploit existing third-party relationships to breach target organisations.
Used by APT28, APT29, menuPass, HAFNIUM, LAPSUS$, Sea Turtle.
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
    technique_id="T1199",
    technique_name="Trusted Relationship",
    tactic_ids=["TA0001"],
    mitre_url="https://attack.mitre.org/techniques/T1199/",
    threat_context=ThreatContext(
        description=(
            "Adversaries exploit established third-party relationships to breach target organisations. "
            "This includes IT service contractors, managed security providers, cloud solution partners, "
            "and Microsoft partners with delegated administrator permissions. Access through trusted "
            "relationships often receives less scrutiny than standard access mechanisms."
        ),
        attacker_goal="Gain initial access by compromising trusted third-party relationships",
        why_technique=[
            "Third-party access often has elevated privileges",
            "Less monitoring than standard user access",
            "Bypasses perimeter security controls",
            "Single compromise enables access to multiple customers",
            "Trusted relationships may lack MFA requirements",
            "Partner accounts persist longer than employee accounts",
        ],
        known_threat_actors=[],
        recent_campaigns=[
            Campaign(
                name="SolarWinds/SUNBURST",
                year=2020,
                description="APT29 exploited compromised cloud partner accounts and fraudulent Mimecast certificates",
                reference_url="https://attack.mitre.org/campaigns/C0024/",
            ),
            Campaign(
                name="Operation Cloud Hopper",
                year=2017,
                description="menuPass abused legitimate MSP access to target downstream customers across multiple industries",
                reference_url="https://attack.mitre.org/groups/G0045/",
            ),
            Campaign(
                name="HAFNIUM Partner Abuse",
                year=2021,
                description="Utilised stolen API keys from privilege access management and cloud app providers",
                reference_url="https://attack.mitre.org/groups/G0125/",
            ),
            Campaign(
                name="Sea Turtle DNS Compromise",
                year=2019,
                description="Targeted DNS registrars, telecommunications companies, and ISPs with trusted relationships",
                reference_url="https://attack.mitre.org/groups/G1041/",
            ),
        ],
        prevalence="uncommon",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Highly effective initial access vector that bypasses perimeter defences. "
            "Single compromise can enable access to multiple downstream customers. "
            "Difficult to detect as activity appears legitimate from trusted sources."
        ),
        business_impact=[
            "Unauthorised access to sensitive systems and data",
            "Reputational damage from third-party breach",
            "Compliance violations (shared responsibility failures)",
            "Supply chain compromise affecting multiple organisations",
            "Difficulty attributing malicious activity to external actors",
        ],
        typical_attack_phase="initial_access",
        often_precedes=["T1078.004", "T1098.001", "T1087.004", "T1530"],
        often_follows=["T1566", "T1110"],
    ),
    detection_strategies=[
        DetectionStrategy(
            strategy_id="t1199-aws-partner-access",
            name="AWS Partner/Cross-Account Role Assumption Detection",
            description=(
                "Detect when external accounts assume roles in your environment, "
                "particularly partner or vendor accounts with elevated privileges."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.principalId, userIdentity.accountId, requestParameters.roleArn, sourceIPAddress
| filter eventName = "AssumeRole"
| filter userIdentity.accountId != recipientAccountId
| stats count(*) as assume_count,
        count_distinct(sourceIPAddress) as unique_ips,
        earliest(@timestamp) as first_seen,
        latest(@timestamp) as last_seen
  by userIdentity.accountId, requestParameters.roleArn, bin(1h)
| filter assume_count > 3 or unique_ips > 2
| sort last_seen desc""",
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect partner/cross-account role assumption (T1199)

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name
  AlertEmail:
    Type: String

Resources:
  # Step 1: Create SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: Detect cross-account role assumptions
  CrossAccountAssumeRoleFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "AssumeRole" && $.userIdentity.accountId != $.recipientAccountId }'
      MetricTransformations:
        - MetricName: CrossAccountRoleAssumptions
          MetricNamespace: Security/T1199
          MetricValue: "1"

  # Step 3: Alert on suspicious partner access
  PartnerAccessAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1199-TrustedRelationshipAbuse
      AlarmDescription: Unusual cross-account role assumption detected
      MetricName: CrossAccountRoleAssumptions
      Namespace: Security/T1199
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 10
      ComparisonOperator: GreaterThanThreshold
      AlarmActions:
        - !Ref AlertTopic

  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics: [!Ref AlertTopic]
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: cloudwatch.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template="""# AWS: Detect partner/cross-account role assumption (T1199)

variable "cloudtrail_log_group" {
  type        = string
  description = "CloudTrail log group name"
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic for alerts
resource "aws_sns_topic" "partner_alerts" {
  name = "t1199-partner-access-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.partner_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Detect cross-account role assumptions
resource "aws_cloudwatch_log_metric_filter" "cross_account_assume" {
  name           = "cross-account-role-assumptions"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventName = \"AssumeRole\" && $.userIdentity.accountId != $.recipientAccountId }"

  metric_transformation {
    name      = "CrossAccountRoleAssumptions"
    namespace = "Security/T1199"
    value     = "1"
  }
}

# Step 3: Alert on suspicious partner access
resource "aws_cloudwatch_metric_alarm" "partner_abuse" {
  alarm_name          = "T1199-TrustedRelationshipAbuse"
  alarm_description   = "Unusual cross-account role assumption detected"
  metric_name         = "CrossAccountRoleAssumptions"
  namespace           = "Security/T1199"
  statistic           = "Sum"
  period              = 300
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.partner_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.partner_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.partner_alerts.arn
    }]
  })
}""",
                alert_severity="high",
                alert_title="Trusted Relationship: Suspicious Partner Access",
                alert_description_template=(
                    "Cross-account role assumption detected from account {userIdentity.accountId} "
                    "to role {requestParameters.roleArn}. {assume_count} assumptions from {unique_ips} IPs."
                ),
                investigation_steps=[
                    "Identify the external AWS account assuming the role",
                    "Review the role's trust policy to confirm authorised partners",
                    "Check all API calls made after role assumption",
                    "Verify the source IPs against known partner infrastructure",
                    "Contact the partner organisation to confirm legitimate access",
                    "Review session duration and accessed resources",
                    "Check for unusual data access or configuration changes",
                ],
                containment_actions=[
                    "Revoke active STS sessions for the assumed role",
                    "Update role trust policy to remove suspicious accounts",
                    "Enable MFA requirement in trust policy conditions",
                    "Add IP address restrictions to trust policy",
                    "Temporarily disable the cross-account role if unauthorised",
                    "Rotate any credentials accessed during the session",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist known partner account IDs and typical access patterns",
            detection_coverage="80% - catches cross-account role assumptions",
            evasion_considerations="Attackers may gradually increase activity to blend with normal patterns",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-45 minutes",
            estimated_monthly_cost="$5-10 depending on log volume",
            prerequisites=[
                "CloudTrail enabled",
                "CloudTrail logs sent to CloudWatch Logs",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1199-aws-delegated-admin",
            name="AWS Organisations Delegated Administrator Activity Detection",
            description=(
                "Monitor for delegated administrator actions that could indicate "
                "compromised partner or vendor accounts with organisation-wide access."
            ),
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.organizations"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "RegisterDelegatedAdministrator",
                            "DeregisterDelegatedAdministrator",
                            "EnableAWSServiceAccess",
                            "DisableAWSServiceAccess",
                        ]
                    },
                },
                terraform_template="""# AWS: Monitor delegated administrator activity (T1199)

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "delegated_admin_alerts" {
  name = "t1199-delegated-admin-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.delegated_admin_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Create EventBridge rule for delegated admin changes
resource "aws_cloudwatch_event_rule" "delegated_admin" {
  name        = "t1199-delegated-admin-monitoring"
  description = "Detect delegated administrator changes"
  event_pattern = jsonencode({
    source      = ["aws.organizations"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "RegisterDelegatedAdministrator",
        "DeregisterDelegatedAdministrator",
        "EnableAWSServiceAccess",
        "DisableAWSServiceAccess"
      ]
    }
  })
}

# Step 3: Route to SNS for alerting
resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.delegated_admin.name
  arn  = aws_sns_topic.delegated_admin_alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.delegated_admin_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.delegated_admin_alerts.arn
    }]
  })
}""",
                alert_severity="critical",
                alert_title="Trusted Relationship: Delegated Administrator Change",
                alert_description_template=(
                    "Delegated administrator action detected: {eventName} by {userIdentity.principalId}. "
                    "Account: {requestParameters.accountId}. Service: {requestParameters.servicePrincipal}."
                ),
                investigation_steps=[
                    "Identify who made the delegated administrator change",
                    "Verify if the change was authorised through change management",
                    "Review which account received delegated admin permissions",
                    "Check all subsequent API calls from the delegated account",
                    "Verify the account belongs to a legitimate partner/vendor",
                    "Review service principal access scope",
                ],
                containment_actions=[
                    "Deregister unauthorised delegated administrators immediately",
                    "Review and revoke any policies or resources created",
                    "Enable SCPs to restrict delegated admin capabilities",
                    "Require MFA and approval workflow for delegated admin changes",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Very low false positives - these actions are rare and should be tracked",
            detection_coverage="100% - captures all delegated admin changes",
            evasion_considerations="Cannot evade if CloudTrail is enabled and protected",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["AWS Organisations enabled", "CloudTrail enabled"],
        ),
        DetectionStrategy(
            strategy_id="t1199-aws-support-access",
            name="AWS Support API Access Detection",
            description=(
                "Detect when third-party support tools or vendors access AWS Support APIs, "
                "which can be abused to gather account information or escalate privileges."
            ),
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query="""fields @timestamp, userIdentity.arn, sourceIPAddress, eventName
| filter eventSource = "support.amazonaws.com"
| filter eventName in ["DescribeCases", "CreateCase", "DescribeServices", "DescribeTrustedAdvisorChecks"]
| stats count(*) as api_calls,
        count_distinct(eventName) as unique_actions,
        count_distinct(sourceIPAddress) as unique_ips
  by userIdentity.arn, bin(1h)
| filter api_calls > 5 or unique_actions > 2
| sort @timestamp desc""",
                terraform_template="""# AWS: Monitor third-party support access (T1199)

variable "cloudtrail_log_group" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create SNS topic
resource "aws_sns_topic" "support_alerts" {
  name = "t1199-support-access-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.support_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Detect AWS Support API access
resource "aws_cloudwatch_log_metric_filter" "support_access" {
  name           = "support-api-access"
  log_group_name = var.cloudtrail_log_group
  pattern        = "{ $.eventSource = \"support.amazonaws.com\" }"

  metric_transformation {
    name      = "SupportAPIAccess"
    namespace = "Security/T1199"
    value     = "1"
  }
}

# Step 3: Alert on unusual support access
resource "aws_cloudwatch_metric_alarm" "support_abuse" {
  alarm_name          = "T1199-SupportAPIAbuse"
  alarm_description   = "Unusual AWS Support API access detected"
  metric_name         = "SupportAPIAccess"
  namespace           = "Security/T1199"
  statistic           = "Sum"
  period              = 3600
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  alarm_actions       = [aws_sns_topic.support_alerts.arn]
}

resource "aws_sns_topic_policy" "allow_cloudwatch" {
  arn = aws_sns_topic.support_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.support_alerts.arn
    }]
  })
}""",
                alert_severity="medium",
                alert_title="Trusted Relationship: Unusual Support Access",
                alert_description_template=(
                    "AWS Support API accessed {api_calls} times by {userIdentity.arn}. "
                    "{unique_actions} different actions from {unique_ips} IPs."
                ),
                investigation_steps=[
                    "Identify which principal accessed Support APIs",
                    "Check if access is from authorised support vendor",
                    "Review what information was accessed via Support APIs",
                    "Verify source IP matches vendor infrastructure",
                    "Check for correlation with support tickets",
                    "Review whether account has active support contracts",
                ],
                containment_actions=[
                    "Revoke IAM permissions for support:* actions if unauthorised",
                    "Review and close any suspicious support cases",
                    "Contact AWS Support to report potential abuse",
                    "Implement IAM condition keys to restrict Support access",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Filter legitimate support vendor access during active tickets",
            detection_coverage="70% - detects Support API abuse",
            evasion_considerations="Low-volume access may not trigger detection",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30-45 minutes",
            estimated_monthly_cost="$3-8",
            prerequisites=[
                "CloudTrail enabled",
                "CloudTrail logs sent to CloudWatch Logs",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1199-gcp-shared-vpc",
            name="GCP Shared VPC and Partner Interconnect Monitoring",
            description=(
                "Detect when external organisations access resources via Shared VPC "
                "or when Partner Interconnect connections are established."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="compute.googleapis.com"
(protoPayload.methodName=~"(attachSharedVpc|detachSharedVpc|createInterconnectAttachment|deleteInterconnectAttachment)"
OR protoPayload.methodName=~"(setIamPolicy|getIamPolicy)")
resource.type="gce_network"''',
                gcp_terraform_template="""# GCP: Monitor shared VPC and partner access (T1199)

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "T1199 Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create log metric for shared VPC/partner access
resource "google_logging_metric" "partner_access" {
  name   = "t1199-partner-network-access"
  filter = <<-EOT
    protoPayload.serviceName="compute.googleapis.com"
    (protoPayload.methodName=~"(attachSharedVpc|detachSharedVpc|createInterconnectAttachment|deleteInterconnectAttachment)"
    OR protoPayload.methodName=~"(setIamPolicy|getIamPolicy)")
    resource.type="gce_network"
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Create alert policy for partner access
resource "google_monitoring_alert_policy" "partner_access" {
  display_name = "T1199: Trusted Relationship Network Access"
  combiner     = "OR"
  conditions {
    display_name = "Shared VPC or partner interconnect activity"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.partner_access.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
  alert_strategy {
    auto_close = "604800s"  # 7 days
  }
}""",
                alert_severity="high",
                alert_title="GCP: Trusted Relationship Network Access",
                alert_description_template=(
                    "Shared VPC or Partner Interconnect activity detected: {methodName} "
                    "by {principalEmail} on network {resource.name}."
                ),
                investigation_steps=[
                    "Identify which external organisation has access",
                    "Review Shared VPC host project IAM policies",
                    "Check all service projects attached to host VPC",
                    "Verify Partner Interconnect connection legitimacy",
                    "Review network routes and firewall rules",
                    "Check for unusual resource creation in shared networks",
                    "Verify access aligns with contractual agreements",
                ],
                containment_actions=[
                    "Detach unauthorised service projects from Shared VPC",
                    "Delete suspicious Partner Interconnect attachments",
                    "Review and restrict network IAM permissions",
                    "Enable VPC Service Controls for additional isolation",
                    "Implement organisation policy constraints for Shared VPC",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="These network changes are rare and should be tracked",
            detection_coverage="90% - captures network-level partner access",
            evasion_considerations="Cannot evade if Cloud Audit Logs enabled",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="45 minutes - 1 hour",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Shared VPC or Partner Interconnect in use",
            ],
        ),
        DetectionStrategy(
            strategy_id="t1199-gcp-marketplace",
            name="GCP Marketplace Third-Party Application Monitoring",
            description=(
                "Monitor installation and permissions granted to third-party GCP Marketplace "
                "applications that could provide vendor access to your environment."
            ),
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query="""protoPayload.serviceName="serviceusage.googleapis.com"
protoPayload.methodName=~"(EnableService|DisableService)"
protoPayload.request.parent=~"projects/"
OR (protoPayload.serviceName="cloudresourcemanager.googleapis.com"
    protoPayload.methodName="SetIamPolicy"
    protoPayload.request.policy.bindings.members=~"serviceAccount.*gserviceaccount.com")""",
                gcp_terraform_template="""# GCP: Monitor third-party marketplace applications (T1199)

variable "project_id" {
  type = string
}

variable "alert_email" {
  type = string
}

# Step 1: Create notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Marketplace Security Alerts"
  type         = "email"
  labels = {
    email_address = var.alert_email
  }
}

# Step 2: Create metric for marketplace activity
resource "google_logging_metric" "marketplace_apps" {
  name   = "t1199-marketplace-activity"
  filter = <<-EOT
    protoPayload.serviceName="serviceusage.googleapis.com"
    protoPayload.methodName=~"EnableService|DisableService"
    OR (protoPayload.serviceName="cloudresourcemanager.googleapis.com"
        protoPayload.methodName="SetIamPolicy"
        protoPayload.request.policy.bindings.members=~"serviceAccount.*gserviceaccount.com")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert on marketplace installations
resource "google_monitoring_alert_policy" "marketplace_activity" {
  display_name = "T1199: Third-Party Application Activity"
  combiner     = "OR"
  conditions {
    display_name = "Marketplace or service account changes"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.marketplace_apps.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }
  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="medium",
                alert_title="GCP: Third-Party Application Activity",
                alert_description_template=(
                    "Marketplace or service account activity: {methodName} by {principalEmail}. "
                    "Service: {request.name}."
                ),
                investigation_steps=[
                    "Identify which third-party service was enabled/modified",
                    "Review IAM permissions granted to service accounts",
                    "Check if installation aligns with procurement records",
                    "Verify which user authorised the installation",
                    "Review data access granted to the application",
                    "Check vendor security posture and compliance",
                ],
                containment_actions=[
                    "Disable unauthorised marketplace services",
                    "Revoke service account permissions",
                    "Review and delete service account keys",
                    "Implement organisation policy to restrict service enablement",
                    "Require approval workflow for third-party integrations",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Whitelist approved marketplace vendors and service patterns",
            detection_coverage="85% - captures service enablement and IAM changes",
            evasion_considerations="Gradual permission expansion may avoid detection",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="45 minutes - 1 hour",
            estimated_monthly_cost="$8-15",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Organisation policies configured",
            ],
        ),
    ],
    recommended_order=[
        "t1199-aws-delegated-admin",
        "t1199-aws-partner-access",
        "t1199-gcp-shared-vpc",
        "t1199-aws-support-access",
        "t1199-gcp-marketplace",
    ],
    total_effort_hours=4.0,
    coverage_improvement="+20% improvement for Initial Access tactic",
)
