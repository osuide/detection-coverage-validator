"""
T1562 - Impair Defences

Adversaries modify environment components to disable or hinder defensive mechanisms.
Targets include security tools, firewalls, logging, and antivirus systems.
Used by BlackByte, Magic Hound, APT29, Scattered Spider, TeamTNT.
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
    technique_id="T1562",
    technique_name="Impair Defences",
    tactic_ids=["TA0005"],
    mitre_url="https://attack.mitre.org/techniques/T1562/",
    threat_context=ThreatContext(
        description=(
            "Adversaries modify victim environment components to disable or hinder defensive mechanisms. "
            "This encompasses both preventative defences like firewalls and antivirus, as well as detection "
            "capabilities such as logging and alerting. In cloud environments, this includes disabling security "
            "services like GuardDuty, CloudWatch, Security Hub, and Cloud Audit Logs. The technique may also "
            "disrupt routine operations contributing to defensive hygiene, such as blocking updates or disabling "
            "security monitoring agents."
        ),
        attacker_goal="Disable defensive mechanisms to evade detection and enable follow-on attacks",
        why_technique=[
            "Eliminates visibility into attacker activities",
            "Prevents incident detection and alerting",
            "Disables automated security responses",
            "Often performed early in attack chain",
            "Single API call can disable multiple protections",
            "Makes incident investigation difficult",
            "Enables persistent access without detection",
        ],
        known_threat_actors=[
            "BlackByte",
            "Magic Hound",
            "APT29",
            "Scattered Spider",
            "TeamTNT",
            "BOLDMOVE",
        ],
        recent_campaigns=[
            Campaign(
                name="BlackByte Kernel Notify Routine Removal",
                year=2024,
                description="Removed Kernel Notify Routines to bypass endpoint detection and response systems",
                reference_url="https://attack.mitre.org/groups/G1043/",
            ),
            Campaign(
                name="Magic Hound LSA Protection Bypass",
                year=2024,
                description="Disabled LSA protection using registry modifications to weaken Windows security controls and enable credential theft",
                reference_url="https://attack.mitre.org/groups/G0059/",
            ),
            Campaign(
                name="Cloud Defence Evasion Campaign",
                year=2024,
                description="Multiple threat actors observed disabling CloudTrail, GuardDuty, and Security Hub immediately after initial compromise",
                reference_url="https://www.datadoghq.com/state-of-cloud-security/",
            ),
        ],
        prevalence="common",
        trend="increasing",
        severity_score=9,
        severity_reasoning=(
            "Critical technique that blinds defenders and enables follow-on attacks. "
            "Disabling security services eliminates visibility and prevents detection of subsequent malicious activity. "
            "Often indicates active compromise requiring immediate response. "
            "Without defensive mechanisms, incident investigation becomes extremely difficult and attacker dwell time increases significantly."
        ),
        business_impact=[
            "Loss of security monitoring and detection",
            "Inability to investigate incidents",
            "Compliance violations and audit failures",
            "Extended attacker dwell time",
            "Increased breach severity",
            "Regulatory fines for logging gaps",
        ],
        typical_attack_phase="defence_evasion",
        often_precedes=["T1530", "T1537", "T1078.004", "T1486", "T1485"],
        often_follows=["T1078.004", "T1528", "T1098"],
    ),
    detection_strategies=[
        # Strategy 1: AWS - GuardDuty Suspension
        DetectionStrategy(
            strategy_id="t1562-aws-guardduty",
            name="AWS GuardDuty Suspension Detection",
            description="Detect when AWS GuardDuty is disabled, suspended, or modified to reduce coverage.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.guardduty"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "DeleteDetector",
                            "StopMonitoringMembers",
                            "DisassociateFromMasterAccount",
                            "UpdateDetector",
                            "DeleteIPSet",
                            "DeleteThreatIntelSet",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect GuardDuty modifications

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: guardduty-modification-alerts
      Subscription:
        - Protocol: email
          Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule to detect GuardDuty changes
  GuardDutyModRule:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-modifications
      Description: Alert on GuardDuty service modifications
      EventPattern:
        source: [aws.guardduty]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - DeleteDetector
            - StopMonitoringMembers
            - DisassociateFromMasterAccount
            - UpdateDetector
      State: ENABLED
      Targets:
        - Id: AlertTarget
          Arn: !Ref AlertTopic

  # Step 3: Allow EventBridge to publish to SNS
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
                terraform_template="""# Detect GuardDuty modifications

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Step 1: SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "guardduty-modification-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule to detect GuardDuty changes
resource "aws_cloudwatch_event_rule" "guardduty_mod" {
  name        = "guardduty-modifications"
  description = "Alert on GuardDuty service modifications"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "DeleteDetector",
        "StopMonitoringMembers",
        "DisassociateFromMasterAccount",
        "UpdateDetector"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.guardduty_mod.name
  arn  = aws_sns_topic.alerts.arn
}

# Step 3: Allow EventBridge to publish to SNS
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
                alert_severity="critical",
                alert_title="GuardDuty Security Service Modified",
                alert_description_template="GuardDuty detector was modified or disabled by {userIdentity.principalId}.",
                investigation_steps=[
                    "Identify who made the change to GuardDuty",
                    "Verify current GuardDuty detector status",
                    "Check if detector is still active",
                    "Review GuardDuty findings before modification",
                    "Examine other concurrent suspicious activity",
                    "Check for credential compromise indicators",
                ],
                containment_actions=[
                    "Immediately re-enable GuardDuty detector",
                    "Lock down IAM user/role that made the change",
                    "Review and rotate potentially compromised credentials",
                    "Enable GuardDuty in all regions",
                    "Implement SCPs to prevent GuardDuty deletion",
                    "Review all security service states",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised security automation roles",
            detection_coverage="95% - catches all GuardDuty API modification calls",
            evasion_considerations="Attacker may use stolen admin credentials; cannot evade if CloudTrail logs to separate account",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled", "GuardDuty enabled"],
        ),
        # Strategy 2: AWS - Security Hub Disabled
        DetectionStrategy(
            strategy_id="t1562-aws-securityhub",
            name="AWS Security Hub Disablement Detection",
            description="Detect when Security Hub is disabled or standards are suspended.",
            detection_type=DetectionType.EVENTBRIDGE_RULE,
            aws_service="eventbridge",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                event_pattern={
                    "source": ["aws.securityhub"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventName": [
                            "DisableSecurityHub",
                            "DisableImportFindingsForProduct",
                            "BatchDisableStandards",
                            "UpdateSecurityHubConfiguration",
                        ]
                    },
                },
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect Security Hub modifications

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

  # Step 2: EventBridge rule
  SecurityHubModRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.securityhub]
        detail-type: [AWS API Call via CloudTrail]
        detail:
          eventName:
            - DisableSecurityHub
            - DisableImportFindingsForProduct
            - BatchDisableStandards
      Targets:
        - Id: Alert
          Arn: !Ref AlertTopic

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
            Resource: !Ref AlertTopic""",
                terraform_template="""# Detect Security Hub modifications

variable "alert_email" { type = string }

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "securityhub-modification-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: EventBridge rule
resource "aws_cloudwatch_event_rule" "securityhub_mod" {
  name = "securityhub-modifications"
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "DisableSecurityHub",
        "DisableImportFindingsForProduct",
        "BatchDisableStandards"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.securityhub_mod.name
  arn  = aws_sns_topic.alerts.arn
}

# Step 3: Topic policy
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
                alert_severity="critical",
                alert_title="Security Hub Disabled or Modified",
                alert_description_template="Security Hub was disabled or modified by {userIdentity.arn}.",
                investigation_steps=[
                    "Identify the principal that disabled Security Hub",
                    "Check if Security Hub is still active",
                    "Review recent Security Hub findings",
                    "Verify which standards were disabled",
                    "Check for other security service changes",
                ],
                containment_actions=[
                    "Re-enable Security Hub immediately",
                    "Re-enable all security standards",
                    "Isolate compromised credentials",
                    "Review IAM policies for Security Hub permissions",
                    "Implement SCPs to prevent deletion",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised security team roles",
            detection_coverage="95% - catches all Security Hub API calls",
            evasion_considerations="Cannot evade if CloudTrail enabled",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$2-5",
            prerequisites=["CloudTrail enabled"],
        ),
        # Strategy 3: AWS - CloudWatch Agent Termination
        DetectionStrategy(
            strategy_id="t1562-aws-cwagent",
            name="CloudWatch Agent Termination Detection",
            description="Detect when CloudWatch agents stop sending metrics, indicating potential tampering.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="cloudwatch",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Detect CloudWatch agent stops

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

  # Step 2: Alarm for missing agent metrics
  AgentStopAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: cloudwatch-agent-stopped
      AlarmDescription: CloudWatch agent has stopped reporting
      MetricName: mem_used_percent
      Namespace: CWAgent
      Statistic: Average
      Period: 300
      EvaluationPeriods: 2
      Threshold: 0
      ComparisonOperator: LessThanOrEqualToThreshold
      TreatMissingData: breaching
      AlarmActions:
        - !Ref AlertTopic

Outputs:
  AlarmName:
    Value: !Ref AgentStopAlarm""",
                terraform_template="""# Detect CloudWatch agent stops

variable "alert_email" { type = string }

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "cloudwatch-agent-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Alarm for missing agent metrics
resource "aws_cloudwatch_metric_alarm" "agent_stop" {
  alarm_name          = "cloudwatch-agent-stopped"
  alarm_description   = "CloudWatch agent has stopped reporting"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "mem_used_percent"
  namespace           = "CWAgent"
  period              = 300
  statistic           = "Average"
  threshold           = 0
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}""",
                alert_severity="high",
                alert_title="CloudWatch Agent Stopped",
                alert_description_template="CloudWatch agent on instance has stopped reporting metrics.",
                investigation_steps=[
                    "Identify which instances stopped reporting",
                    "Check instance system logs",
                    "Verify agent process status",
                    "Review recent API calls on the instance",
                    "Check for signs of tampering or malware",
                ],
                containment_actions=[
                    "Restart CloudWatch agent",
                    "Investigate instance for compromise",
                    "Review IAM instance profile permissions",
                    "Enable SSM for remote management",
                    "Consider isolating suspicious instances",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Account for planned maintenance windows",
            detection_coverage="80% - detects agent stops but not all tampering methods",
            evasion_considerations="Attacker could send fake metrics; requires agent to be deployed",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["CloudWatch Agent installed on instances"],
        ),
        # Strategy 4: GCP - Security Command Centre Disabled
        DetectionStrategy(
            strategy_id="t1562-gcp-scc",
            name="GCP Security Command Centre Disablement Detection",
            description="Detect when Security Command Centre services or findings are disabled.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''protoPayload.serviceName="securitycenter.googleapis.com"
protoPayload.methodName=~"(UpdateOrganizationSettings|UpdateSource|DeleteNotificationConfig)"
severity="NOTICE"''',
                gcp_terraform_template="""# GCP: Detect Security Command Centre modifications

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

# Step 2: Log-based metric for SCC changes
resource "google_logging_metric" "scc_mod" {
  name   = "scc-modifications"
  filter = <<-EOT
    protoPayload.serviceName="securitycenter.googleapis.com"
    protoPayload.methodName=~"UpdateOrganizationSettings|UpdateSource|DeleteNotificationConfig"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "scc_mod" {
  display_name = "Security Command Centre Modified"
  combiner     = "OR"

  conditions {
    display_name = "SCC configuration changed"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.scc_mod.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]

  alert_strategy {
    auto_close = "604800s"
  }
}""",
                alert_severity="critical",
                alert_title="GCP: Security Command Centre Modified",
                alert_description_template="Security Command Centre configuration was changed.",
                investigation_steps=[
                    "Review what SCC configuration changed",
                    "Identify the principal making the change",
                    "Check if findings are still being generated",
                    "Verify notification configs are active",
                    "Review recent security findings before change",
                ],
                containment_actions=[
                    "Restore SCC configuration",
                    "Re-enable disabled security services",
                    "Lock down SCC permissions",
                    "Review service account permissions",
                    "Enable organisation policy constraints",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised security team accounts",
            detection_coverage="90% - catches API calls to Security Command Centre",
            evasion_considerations="Attacker may use compromised admin account",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$5-10",
            prerequisites=[
                "Cloud Audit Logs enabled",
                "Security Command Centre enabled",
            ],
        ),
        # Strategy 5: GCP - Ops Agent Disabled
        DetectionStrategy(
            strategy_id="t1562-gcp-opsagent",
            name="GCP Ops Agent Disablement Detection",
            description="Detect when Ops Agent (Logging/Monitoring) is stopped or removed from instances.",
            detection_type=DetectionType.CLOUD_LOGGING_QUERY,
            aws_service="n/a",
            gcp_service="cloud_logging",
            cloud_provider=CloudProvider.GCP,
            implementation=DetectionImplementation(
                gcp_logging_query='''resource.type="gce_instance"
jsonPayload.message=~"(stopping|stopped|removed|disabled).*agent"
OR protoPayload.methodName="compute.instances.stop"
OR protoPayload.request.metadata.items.key="enable-oslogin" AND protoPayload.request.metadata.items.value="false"''',
                gcp_terraform_template="""# GCP: Detect Ops Agent disablement

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

# Step 2: Log-based metric for agent stops
resource "google_logging_metric" "agent_stop" {
  name   = "ops-agent-stops"
  filter = <<-EOT
    resource.type="gce_instance"
    jsonPayload.message=~"stopping.*agent|stopped.*agent"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert policy
resource "google_monitoring_alert_policy" "agent_stop" {
  display_name = "Ops Agent Stopped"
  combiner     = "OR"

  conditions {
    display_name = "Monitoring agent stopped"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.agent_stop.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="high",
                alert_title="GCP: Ops Agent Stopped or Disabled",
                alert_description_template="Ops Agent has been stopped or removed from instance.",
                investigation_steps=[
                    "Identify which instances lost agent",
                    "Check instance serial console logs",
                    "Review SSH access logs",
                    "Verify agent installation status",
                    "Check for signs of tampering",
                ],
                containment_actions=[
                    "Reinstall and restart Ops Agent",
                    "Investigate instance for compromise",
                    "Review IAM permissions on instance",
                    "Enable OS Login for better auditing",
                    "Consider instance isolation",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.MEDIUM,
            false_positive_tuning="Exclude planned maintenance and agent updates",
            detection_coverage="75% - depends on agent logs being sent before termination",
            evasion_considerations="Attacker may stop agent before it can log; requires agent pre-installed",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="1 hour",
            estimated_monthly_cost="$5-10",
            prerequisites=["Ops Agent installed", "Cloud Logging enabled"],
        ),
        # Strategy 6: Multi-Cloud - Security Service State Monitoring
        DetectionStrategy(
            strategy_id="t1562-multicloud-state",
            name="Security Service State Baseline Monitoring",
            description="Continuously verify security services remain enabled by comparing against baseline configuration.",
            detection_type=DetectionType.CLOUDWATCH_QUERY,
            aws_service="config",
            gcp_service="cloud_asset",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                query='''# AWS Config Rule to verify GuardDuty, Security Hub, CloudTrail are enabled
fields @timestamp, configurationItem.resourceType, configurationItem.configuration.status
| filter configurationItem.resourceType in ["AWS::GuardDuty::Detector", "AWS::SecurityHub::Hub", "AWS::CloudTrail::Trail"]
| filter configurationItem.configuration.status != "ENABLED"''',
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: Monitor security service state

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

  # Step 2: Config Rule for GuardDuty
  GuardDutyEnabledRule:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: guardduty-enabled-check
      Source:
        Owner: AWS
        SourceIdentifier: GUARDDUTY_ENABLED_CENTRALIZED

  # Step 3: EventBridge for Config compliance changes
  ConfigComplianceRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        source: [aws.config]
        detail-type: [Config Rules Compliance Change]
        detail:
          configRuleName: [guardduty-enabled-check]
          newEvaluationResult:
            complianceType: [NON_COMPLIANT]
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
                terraform_template="""# Monitor security service state with AWS Config

variable "alert_email" { type = string }

# Step 1: SNS topic
resource "aws_sns_topic" "alerts" {
  name = "security-service-state-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Step 2: Config Rule for GuardDuty
resource "aws_config_config_rule" "guardduty_enabled" {
  name = "guardduty-enabled-check"

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Step 3: EventBridge for Config compliance changes
resource "aws_cloudwatch_event_rule" "config_compliance" {
  name = "security-service-compliance"
  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = ["guardduty-enabled-check"]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "sns" {
  rule = aws_cloudwatch_event_rule.config_compliance.name
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
                gcp_terraform_template="""# GCP: Monitor security service state with Cloud Asset Inventory

variable "project_id" { type = string }
variable "organization_id" { type = string }
variable "alert_email" { type = string }

# Step 1: Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Security Alerts"
  type         = "email"
  labels = { email_address = var.alert_email }
}

# Step 2: Log-based metric for security service state changes
resource "google_logging_metric" "security_service_change" {
  name   = "security-service-state-changes"
  filter = <<-EOT
    protoPayload.serviceName=~"securitycenter.googleapis.com|logging.googleapis.com"
    protoPayload.methodName=~"Disable|Delete|Update.*Settings"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Step 3: Alert on state changes
resource "google_monitoring_alert_policy" "service_state" {
  display_name = "Security Service State Changed"
  combiner     = "OR"

  conditions {
    display_name = "Security service modified"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.security_service_change.name}\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  notification_channels = [google_monitoring_notification_channel.email.id]
}""",
                alert_severity="critical",
                alert_title="Security Service State Changed - Service Disabled",
                alert_description_template="Security service state changed to non-compliant or disabled.",
                investigation_steps=[
                    "Identify which security service was disabled",
                    "Check AWS Config timeline for state changes",
                    "Review who disabled the service",
                    "Verify current state of all security services",
                    "Check for other concurrent suspicious changes",
                ],
                containment_actions=[
                    "Re-enable all disabled security services",
                    "Lock down permissions using SCPs",
                    "Rotate compromised credentials",
                    "Enable AWS Config remediation actions",
                    "Review and harden IAM policies",
                ],
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="Whitelist authorised security operations",
            detection_coverage="95% - continuous state monitoring",
            evasion_considerations="Cannot evade continuous compliance checking",
            implementation_effort=EffortLevel.MEDIUM,
            implementation_time="2 hours",
            estimated_monthly_cost="$10-20",
            prerequisites=[
                "AWS Config enabled",
                "Cloud Asset Inventory enabled for GCP",
            ],
        ),
    ],
    recommended_order=[
        "t1562-aws-guardduty",
        "t1562-aws-securityhub",
        "t1562-gcp-scc",
        "t1562-multicloud-state",
        "t1562-aws-cwagent",
        "t1562-gcp-opsagent",
    ],
    total_effort_hours=5.5,
    coverage_improvement="+30% improvement for Defence Evasion tactic",
)
