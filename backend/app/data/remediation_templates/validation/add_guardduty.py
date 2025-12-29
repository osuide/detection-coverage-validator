#!/usr/bin/env python3
"""
Add GuardDuty detection strategies to templates that don't have them.

This script adds GuardDuty-based detection strategies to templates
that have native GuardDuty coverage but don't use it.
"""

import re
from pathlib import Path
from typing import List

# Mapping of techniques to GuardDuty findings and descriptions
GUARDDUTY_ADDITIONS = {
    "t1485_data_destruction.py": {
        "technique_id": "T1485",
        "findings": [
            "Impact:IAMUser/AnomalousBehavior",
            "Impact:S3/MaliciousIPCaller",
        ],
        "description": (
            "AWS GuardDuty detects anomalous data destruction patterns including "
            "unusual DeleteObject, DeleteBucket, or other destructive API calls. "
            "Impact:IAMUser/AnomalousBehavior identifies when destructive APIs are "
            "invoked in unusual patterns suggesting malicious activity."
        ),
    },
    "t1486_data_encrypted_for_impact.py": {
        "technique_id": "T1486",
        "findings": [
            "Impact:IAMUser/AnomalousBehavior",
        ],
        "description": (
            "AWS GuardDuty detects anomalous encryption-related activities that may "
            "indicate ransomware or data encryption for impact. The anomaly detection "
            "identifies unusual KMS or encryption API patterns."
        ),
    },
    "t1526_cloud_service_discovery.py": {
        "technique_id": "T1526",
        "findings": [
            "Discovery:IAMUser/AnomalousBehavior",
        ],
        "description": (
            "AWS GuardDuty detects anomalous cloud service discovery activity. "
            "Discovery:IAMUser/AnomalousBehavior identifies when service enumeration "
            "APIs like DescribeInstances, ListBuckets, or ListFunctions are called "
            "in unusual patterns."
        ),
    },
    "t1136_create_account.py": {
        "technique_id": "T1136",
        "findings": [
            "Persistence:IAMUser/AnomalousBehavior",
        ],
        "description": (
            "AWS GuardDuty detects anomalous account creation patterns. "
            "Persistence:IAMUser/AnomalousBehavior identifies when CreateUser, "
            "CreateAccessKey, or similar APIs are invoked in unusual patterns "
            "suggesting unauthorised persistence establishment."
        ),
    },
    "t1087_account_discovery.py": {
        "technique_id": "T1087",
        "findings": [
            "Discovery:IAMUser/AnomalousBehavior",
        ],
        "description": (
            "AWS GuardDuty detects anomalous account enumeration. "
            "Discovery:IAMUser/AnomalousBehavior identifies when ListUsers, "
            "GetUser, ListAccessKeys, or similar discovery APIs are called "
            "in patterns suggesting reconnaissance."
        ),
    },
    "t1498_network_dos.py": {
        "technique_id": "T1498",
        "findings": [
            "Backdoor:EC2/DenialOfService.Dns",
            "Backdoor:EC2/DenialOfService.Tcp",
            "Backdoor:EC2/DenialOfService.Udp",
            "Backdoor:EC2/DenialOfService.UdpOnTcpPorts",
        ],
        "description": (
            "AWS GuardDuty detects when EC2 instances are participating in "
            "denial of service attacks. These findings indicate that an instance "
            "may be compromised and being used to conduct network floods."
        ),
    },
    "t1070_indicator_removal.py": {
        "technique_id": "T1070",
        "findings": [
            "DefenseEvasion:IAMUser/AnomalousBehavior",
            "Stealth:IAMUser/CloudTrailLoggingDisabled",
        ],
        "description": (
            "AWS GuardDuty detects defence evasion and indicator removal. "
            "DefenseEvasion:IAMUser/AnomalousBehavior identifies anomalous calls to "
            "APIs like DeleteFlowLogs, StopLogging, or DisableAlarmActions. "
            "Stealth:IAMUser/CloudTrailLoggingDisabled fires when CloudTrail is disabled."
        ),
    },
    "t1568_002_domain_generation_algorithms.py": {
        "technique_id": "T1568.002",
        "findings": [
            "Trojan:EC2/DGADomainRequest.B",
            "Trojan:EC2/DGADomainRequest.C!DNS",
        ],
        "description": (
            "AWS GuardDuty uses ML to detect domain generation algorithm (DGA) "
            "communications. These findings fire when EC2 instances query domains "
            "that match DGA patterns, indicating potential C2 communication."
        ),
    },
    "t1548_abuse_elevation.py": {
        "technique_id": "T1548",
        "findings": [
            "PrivilegeEscalation:IAMUser/AnomalousBehavior",
        ],
        "description": (
            "AWS GuardDuty detects privilege escalation attempts. "
            "PrivilegeEscalation:IAMUser/AnomalousBehavior identifies when APIs "
            "like AssociateIamInstanceProfile, AddUserToGroup, or AttachRolePolicy "
            "are called in patterns suggesting unauthorised privilege elevation."
        ),
    },
    "t1048_exfil_alt_protocol.py": {
        "technique_id": "T1048",
        "findings": [
            "Behavior:EC2/TrafficVolumeUnusual",
            "Trojan:EC2/DNSDataExfiltration",
        ],
        "description": (
            "AWS GuardDuty detects exfiltration over alternative protocols. "
            "Behavior:EC2/TrafficVolumeUnusual identifies unusual outbound data volumes. "
            "Trojan:EC2/DNSDataExfiltration detects DNS tunnelling for data exfiltration."
        ),
    },
}


def generate_guardduty_strategy(
    technique_id: str, findings: List[str], description: str
) -> str:
    """Generate a GuardDuty detection strategy code block."""
    findings_str = ",\n                    ".join(f'"{f}"' for f in findings)

    strategy = f'''        # AWS GuardDuty Detection (Recommended)
        DetectionStrategy(
            strategy_id="{technique_id.lower()}-aws-guardduty",
            name="AWS GuardDuty Anomaly Detection",
            description=(
                "{description}"
            ),
            detection_type=DetectionType.GUARDDUTY,
            aws_service="guardduty",
            cloud_provider=CloudProvider.AWS,
            implementation=DetectionImplementation(
                guardduty_finding_types=[
                    {findings_str},
                ],
                cloudformation_template="""AWSTemplateFormatVersion: '2010-09-09'
Description: GuardDuty alerts for {technique_id}

Parameters:
  AlertEmail:
    Type: String
    Description: Email for security alerts

Resources:
  # Step 1: SNS Topic for alerts
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: GuardDuty-{technique_id}-Alerts
      KmsMasterKeyId: alias/aws/sns

  AlertSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref AlertTopic
      Protocol: email
      Endpoint: !Ref AlertEmail

  # Step 2: EventBridge rule for GuardDuty findings
  GuardDutyRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Capture GuardDuty findings for {technique_id}
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          type:
            - prefix: "{findings[0].split('/')[0]}/"
      State: ENABLED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertTopic

  # Step 3: Allow EventBridge to publish to SNS
  TopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertTopic
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertTopic""",
                terraform_template=\"\"\"# GuardDuty alerts for {technique_id}

variable "alert_email" {{
  type        = string
  description = "Email for security alerts"
}}

data "aws_caller_identity" "current" {{}}

# Step 1: SNS Topic
resource "aws_sns_topic" "guardduty_alerts" {{
  name              = "guardduty-{technique_id.lower()}-alerts"
  kms_master_key_id = "alias/aws/sns"
}}

resource "aws_sns_topic_subscription" "email" {{
  topic_arn = aws_sns_topic.guardduty_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}}

# Step 2: EventBridge rule for findings
resource "aws_cloudwatch_event_rule" "guardduty" {{
  name        = "guardduty-{technique_id.lower()}"
  description = "Capture GuardDuty findings for {technique_id}"

  event_pattern = jsonencode({{
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {{
      type = [{{ prefix = "{findings[0].split('/')[0]}/" }}]
    }}
  }})
}}

# Step 3: Target with DLQ and retry
resource "aws_sqs_queue" "dlq" {{
  name                      = "guardduty-{technique_id.lower()}-dlq"
  message_retention_seconds = 1209600
}}

resource "aws_cloudwatch_event_target" "sns" {{
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "SNSTarget"
  arn       = aws_sns_topic.guardduty_alerts.arn

  retry_policy {{
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 8
  }}

  dead_letter_config {{
    arn = aws_sqs_queue.dlq.arn
  }}
}}

# Step 4: SNS topic policy
resource "aws_sns_topic_policy" "allow_eventbridge" {{
  arn = aws_sns_topic.guardduty_alerts.arn
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect    = "Allow"
      Principal = {{ Service = "events.amazonaws.com" }}
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.guardduty_alerts.arn
      Condition = {{
        StringEquals = {{ "AWS:SourceAccount" = data.aws_caller_identity.current.account_id }}
        ArnEquals    = {{ "aws:SourceArn" = aws_cloudwatch_event_rule.guardduty.arn }}
      }}
    }}]
  }})
}}\"\"\",
            ),
            estimated_false_positive_rate=FalsePositiveRate.LOW,
            false_positive_tuning="GuardDuty uses ML baselines; tune suppression rules for known benign patterns",
            detection_coverage="70% - detects anomalous behaviour but may miss attacks that blend with normal activity",
            implementation_effort=EffortLevel.LOW,
            implementation_time="30 minutes",
            estimated_monthly_cost="$4-10 per million events",
            prerequisites=[
                "AWS GuardDuty enabled",
                "CloudTrail logging active",
            ],
        ),'''

    return strategy


def add_guardduty_to_template(template_path: Path, info: dict) -> bool:
    """Add GuardDuty strategy to a template. Returns True if changes made."""
    content = template_path.read_text()

    # Check if already has GuardDuty
    if "GUARDDUTY" in content or "guardduty_finding_types" in content:
        print(f"  Already has GuardDuty: {template_path.name}")
        return False

    # Find the detection_strategies list
    match = re.search(r"detection_strategies=\[\s*\n", content)
    if not match:
        print(f"  Could not find detection_strategies: {template_path.name}")
        return False

    # Generate the strategy
    strategy = generate_guardduty_strategy(
        info["technique_id"], info["findings"], info["description"]
    )

    # Insert after detection_strategies=[
    insert_pos = match.end()
    new_content = content[:insert_pos] + strategy + "\n" + content[insert_pos:]

    template_path.write_text(new_content)
    return True


def main() -> None:
    """Add GuardDuty to templates that need it."""
    templates_dir = Path(__file__).parent.parent

    for template_name, info in GUARDDUTY_ADDITIONS.items():
        template_path = templates_dir / template_name
        if template_path.exists():
            print(f"Processing: {template_name}")
            if add_guardduty_to_template(template_path, info):
                print("  ✅ Added GuardDuty strategy")
            else:
                print("  ⏭️  Skipped")
        else:
            print(f"  ❌ Not found: {template_name}")


if __name__ == "__main__":
    main()
