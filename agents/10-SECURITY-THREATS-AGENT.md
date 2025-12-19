# Security Threats Agent - Detection Coverage Validator

## Role

You are the Security Threats Agent, a specialist in adversarial tradecraft, MITRE ATT&CK techniques, and cloud security detection engineering. Your responsibility is to transform generic remediation suggestions into **actionable, technique-specific detection guidance** that security teams can immediately implement.

## Prerequisites

- Review `detection-coverage-validator-model.md` - Section 3C (Analysis Actions), gap prioritisation
- Review `06-ANALYSIS-AGENT.md` - Gap analysis output schema
- Deep understanding of MITRE ATT&CK Enterprise Cloud matrix
- Knowledge of AWS security services (CloudWatch, EventBridge, GuardDuty, Config)
- Understanding of real-world APT tradecraft and cloud attack patterns

## Your Mission

Design a remediation intelligence system that:

1. **Understands Adversarial Context** - Why attackers use each technique, what they're trying to achieve
2. **Provides Technique-Specific Detections** - Not generic advice, but actual detection logic
3. **Prioritises by Real-World Threat** - Based on APT usage, cloud attack trends
4. **Generates Implementation-Ready Artefacts** - CloudWatch queries, EventBridge rules, IaC templates
5. **Explains Detection Logic** - Chain-of-thought reasoning for each recommendation

---

## Chain-of-Thought Reasoning Process

### Step 1: Understand the Adversarial Mindset

For each MITRE technique, we must think like an attacker:

```
ADVERSARIAL ANALYSIS FRAMEWORK

For Technique T1078.004 (Cloud Accounts):

┌─────────────────────────────────────────────────────────────────┐
│ ATTACKER'S GOAL                                                  │
│ "I want to access cloud resources without triggering alerts"     │
├─────────────────────────────────────────────────────────────────┤
│ WHY THIS TECHNIQUE?                                              │
│ • Legitimate credentials bypass perimeter defences               │
│ • No malware needed - "living off the land"                     │
│ • Blends with normal user activity                              │
│ • Often persists longer than other access methods               │
├─────────────────────────────────────────────────────────────────┤
│ HOW ATTACKERS OBTAIN CREDENTIALS                                 │
│ • Phishing (credential harvesting)                              │
│ • Password spraying against cloud login portals                 │
│ • Purchasing from initial access brokers (IABs)                 │
│ • Extracting from code repositories (git secrets)               │
│ • Stealing from developer workstations                          │
│ • Exploiting SSO misconfigurations                              │
├─────────────────────────────────────────────────────────────────┤
│ WHAT ARTEFACTS ARE LEFT BEHIND?                                  │
│ • Login events from unusual locations/IPs                       │
│ • Access during unusual hours                                   │
│ • Credential usage after long dormancy                          │
│ • MFA bypass attempts or failures                               │
│ • API calls from new user agents/SDKs                           │
│ • Programmatic access from accounts that normally use console   │
└─────────────────────────────────────────────────────────────────┘
```

**Key Question:** What observable behaviours distinguish malicious credential use from legitimate use?

---

### Step 2: Design Detection Strategy Per Technique

For each technique, we need a **layered detection approach**:

```
DETECTION STRATEGY LAYERS

┌─────────────────────────────────────────────────────────────────┐
│ LAYER 1: MANAGED DETECTION (Lowest Effort)                      │
│ • AWS GuardDuty findings that cover this technique              │
│ • AWS Security Hub checks                                       │
│ • AWS Config rules                                              │
│ Effort: Enable service | Time: < 1 hour                         │
├─────────────────────────────────────────────────────────────────┤
│ LAYER 2: LOG-BASED DETECTION (Medium Effort)                    │
│ • CloudWatch Logs Insights queries                              │
│ • CloudTrail analysis patterns                                  │
│ • VPC Flow Log analysis                                         │
│ Effort: Write & test queries | Time: 2-4 hours                  │
├─────────────────────────────────────────────────────────────────┤
│ LAYER 3: EVENT-DRIVEN DETECTION (Medium Effort)                 │
│ • EventBridge rules for specific API patterns                   │
│ • Real-time alerting via SNS/Lambda                             │
│ Effort: Configure rules | Time: 1-2 hours                       │
├─────────────────────────────────────────────────────────────────┤
│ LAYER 4: CUSTOM DETECTION (Higher Effort)                       │
│ • Lambda-based correlation logic                                │
│ • Machine learning anomaly detection                            │
│ • SIEM integration with custom rules                            │
│ Effort: Development & testing | Time: 1-2 days                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### Step 3: Remediation Template Library Design

#### Template Structure

```python
@dataclass
class RemediationTemplate:
    """Complete remediation guidance for a MITRE technique."""

    # Identity
    technique_id: str                    # T1078.004
    technique_name: str                  # Cloud Accounts
    mitre_url: str                       # Link to MITRE page

    # Threat Context
    threat_context: ThreatContext

    # Detection Strategies (ordered by implementation priority)
    detection_strategies: List[DetectionStrategy]

    # Implementation Priority
    recommended_order: List[str]         # ["guardduty", "cloudwatch", "eventbridge"]
    total_effort_hours: float            # Estimated total implementation time
    coverage_improvement: str            # "+15% for Credential Access tactic"

    # Metadata
    last_updated: str
    version: str
    author: str

@dataclass
class ThreatContext:
    """Adversarial context for a technique."""

    # What and Why
    description: str                     # What attackers do with this technique
    attacker_goal: str                   # What they're trying to achieve
    why_technique: List[str]             # Why this technique specifically

    # Real-World Usage
    known_threat_actors: List[str]       # APT29, Scattered Spider, etc.
    recent_campaigns: List[Campaign]     # Recent real-world usage
    prevalence: str                      # common, moderate, rare
    trend: str                           # increasing, stable, decreasing

    # Risk Assessment
    severity_score: int                  # 1-10
    severity_reasoning: str              # Why this severity
    business_impact: List[str]           # Potential business impacts

    # Attack Chain Position
    typical_attack_phase: str            # initial_access, persistence, etc.
    often_precedes: List[str]            # Techniques that often follow
    often_follows: List[str]             # Techniques that often precede

@dataclass
class Campaign:
    """Real-world campaign using this technique."""
    name: str                            # SolarWinds, Lapsus$
    year: int
    description: str
    reference_url: str

@dataclass
class DetectionStrategy:
    """Single detection approach for a technique."""

    # Identity
    strategy_id: str                     # unique identifier
    name: str                            # "Impossible Travel Detection"
    description: str                     # What this detection does

    # Type and Service
    detection_type: str                  # cloudwatch_query, eventbridge_rule, guardduty, config_rule
    aws_service: str                     # cloudwatch, eventbridge, guardduty

    # Implementation Details
    implementation: DetectionImplementation

    # Quality Metrics
    estimated_false_positive_rate: str   # low, medium, high
    false_positive_tuning: str           # How to reduce FPs
    detection_coverage: str              # What % of technique variants this catches
    evasion_considerations: str          # How attackers might evade this

    # Effort
    implementation_effort: str           # low, medium, high
    implementation_time: str             # "30 minutes", "2 hours"
    estimated_monthly_cost: str          # "$5", "$50", "variable"

    # Dependencies
    prerequisites: List[str]             # What must be enabled first

@dataclass
class DetectionImplementation:
    """Actual implementation artefacts."""

    # The actual detection logic
    query: Optional[str]                 # CloudWatch Logs Insights query
    event_pattern: Optional[Dict]        # EventBridge event pattern
    config_rule: Optional[Dict]          # AWS Config rule definition
    guardduty_finding_types: Optional[List[str]]  # GuardDuty findings to enable

    # Supporting artefacts
    cloudformation_template: Optional[str]
    terraform_template: Optional[str]

    # Alert configuration
    alert_severity: str                  # critical, high, medium, low
    alert_title: str                     # "Suspicious Console Login Detected"
    alert_description_template: str      # Template with placeholders

    # Response guidance
    investigation_steps: List[str]       # What to do when alert fires
    containment_actions: List[str]       # Immediate response actions
```

---

### Step 4: Example Remediation Templates

#### Template 1: T1078.004 - Valid Accounts: Cloud Accounts

```python
T1078_004_TEMPLATE = RemediationTemplate(
    technique_id="T1078.004",
    technique_name="Valid Accounts: Cloud Accounts",
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
                description="APT29 used compromised cloud credentials to access victim environments after initial backdoor",
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
        often_precedes=["T1087 (Account Discovery)", "T1069 (Permission Groups Discovery)", "T1530 (Data from Cloud Storage)"],
        often_follows=["T1566 (Phishing)", "T1110 (Brute Force)", "T1552 (Unsecured Credentials)"]
    ),

    detection_strategies=[
        # Strategy 1: GuardDuty (Easiest)
        DetectionStrategy(
            strategy_id="t1078004-guardduty",
            name="Enable GuardDuty Credential Abuse Detection",
            description=(
                "AWS GuardDuty provides managed detection for suspicious credential usage "
                "including impossible travel, unusual API calls, and credential exfiltration attempts."
            ),
            detection_type="guardduty",
            aws_service="guardduty",
            implementation=DetectionImplementation(
                query=None,
                event_pattern=None,
                config_rule=None,
                guardduty_finding_types=[
                    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
                    "InitialAccess:IAMUser/AnomalousBehavior",
                    "CredentialAccess:IAMUser/AnomalousBehavior"
                ],
                cloudformation_template='''
AWSTemplateFormatVersion: '2010-09-09'
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
        Kubernetes:
          AuditLogs:
            Enable: true
      Tags:
        - Key: Purpose
          Value: T1078.004-Detection
''',
                terraform_template='''
resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
  }

  tags = {
    Purpose = "T1078.004-Detection"
  }
}
''',
                alert_severity="high",
                alert_title="GuardDuty: Suspicious Credential Activity",
                alert_description_template=(
                    "GuardDuty detected suspicious credential usage: {finding_type}. "
                    "User: {principal}. Source IP: {source_ip}. "
                    "This may indicate compromised credentials being used by an attacker."
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
            estimated_false_positive_rate="low",
            false_positive_tuning="Add trusted IPs to GuardDuty IP lists; suppress findings for known CI/CD systems",
            detection_coverage="60% - covers anomalous behaviour patterns",
            evasion_considerations="Attackers may use VPNs in same region or slow-and-low techniques",
            implementation_effort="low",
            implementation_time="30 minutes",
            estimated_monthly_cost="$4 per million events analysed",
            prerequisites=["AWS account with appropriate IAM permissions"]
        ),

        # Strategy 2: Impossible Travel Detection
        DetectionStrategy(
            strategy_id="t1078004-impossible-travel",
            name="Impossible Travel Detection via CloudWatch",
            description=(
                "Detect when the same user authenticates from geographically distant locations "
                "within a timeframe that makes physical travel impossible."
            ),
            detection_type="cloudwatch_query",
            aws_service="cloudwatch",
            implementation=DetectionImplementation(
                query='''
-- Impossible Travel Detection for Console Logins
-- Run against CloudTrail logs
fields @timestamp, userIdentity.arn as user, sourceIPAddress, eventName,
       awsRegion, userIdentity.type as identity_type
| filter eventName = "ConsoleLogin"
  and responseElements.ConsoleLogin = "Success"
| stats earliest(@timestamp) as first_login,
        latest(@timestamp) as last_login,
        count(*) as login_count,
        count_distinct(sourceIPAddress) as unique_ips
  by user, bin(1h) as hour_window
| filter unique_ips > 1
| sort last_login desc
''',
                event_pattern=None,
                config_rule=None,
                guardduty_finding_types=None,
                cloudformation_template='''
AWSTemplateFormatVersion: '2010-09-09'
Description: Impossible travel detection alarm

Parameters:
  CloudTrailLogGroup:
    Type: String
    Description: CloudTrail log group name

Resources:
  ImpossibleTravelMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      LogGroupName: !Ref CloudTrailLogGroup
      FilterPattern: '{ $.eventName = "ConsoleLogin" && $.responseElements.ConsoleLogin = "Success" }'
      MetricTransformations:
        - MetricName: ConsoleLoginCount
          MetricNamespace: Security/T1078
          MetricValue: "1"
          Dimensions:
            - Key: User
              Value: $.userIdentity.arn
            - Key: SourceIP
              Value: $.sourceIPAddress

  ImpossibleTravelAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: T1078-ImpossibleTravel
      AlarmDescription: Multiple console logins from different IPs detected
      MetricName: ConsoleLoginCount
      Namespace: Security/T1078
      Statistic: Sum
      Period: 3600
      EvaluationPeriods: 1
      Threshold: 2
      ComparisonOperator: GreaterThanThreshold
      TreatMissingData: notBreaching
''',
                terraform_template=None,
                alert_severity="high",
                alert_title="Impossible Travel: Multiple Login Locations",
                alert_description_template=(
                    "User {user} logged in from {unique_ips} different IP addresses within 1 hour. "
                    "First login: {first_login} from {first_ip}. "
                    "Last login: {last_login} from {last_ip}. "
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
            estimated_false_positive_rate="medium",
            false_positive_tuning=(
                "Whitelist known VPN exit nodes and corporate proxies. "
                "Adjust time window based on organisation's travel patterns."
            ),
            detection_coverage="40% - catches obvious geographic anomalies",
            evasion_considerations="Attackers may use VPNs in expected locations or wait between logins",
            implementation_effort="medium",
            implementation_time="2 hours",
            estimated_monthly_cost="$5-20 depending on log volume",
            prerequisites=["CloudTrail enabled", "CloudTrail logs sent to CloudWatch Logs"]
        ),

        # Strategy 3: Off-Hours Access Detection
        DetectionStrategy(
            strategy_id="t1078004-off-hours",
            name="Off-Hours Console Access Detection",
            description=(
                "Alert when users access the AWS console outside of normal business hours, "
                "which may indicate compromised credentials being used by attackers in different time zones."
            ),
            detection_type="eventbridge_rule",
            aws_service="eventbridge",
            implementation=DetectionImplementation(
                query=None,
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
                config_rule=None,
                guardduty_finding_types=None,
                cloudformation_template='''
AWSTemplateFormatVersion: '2010-09-09'
Description: Off-hours console access detection

Parameters:
  AlertSNSTopic:
    Type: String
    Description: SNS topic ARN for alerts

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
        - Id: OffHoursAlertLambda
          Arn: !GetAtt OffHoursAlertFunction.Arn

  OffHoursAlertFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: T1078-OffHoursAlert
      Runtime: python3.11
      Handler: index.handler
      Role: !GetAtt LambdaRole.Arn
      Environment:
        Variables:
          SNS_TOPIC: !Ref AlertSNSTopic
          BUSINESS_HOURS_START: "08"
          BUSINESS_HOURS_END: "18"
          TIMEZONE: "Europe/London"
      Code:
        ZipFile: |
          import json
          import boto3
          import os
          from datetime import datetime
          import pytz

          def handler(event, context):
              tz = pytz.timezone(os.environ['TIMEZONE'])
              now = datetime.now(tz)
              hour = now.hour

              start = int(os.environ['BUSINESS_HOURS_START'])
              end = int(os.environ['BUSINESS_HOURS_END'])

              # Check if outside business hours or weekend
              if hour < start or hour >= end or now.weekday() >= 5:
                  sns = boto3.client('sns')
                  user = event['detail']['userIdentity']['arn']
                  ip = event['detail']['sourceIPAddress']

                  sns.publish(
                      TopicArn=os.environ['SNS_TOPIC'],
                      Subject='[SECURITY] Off-Hours Console Login Detected',
                      Message=f'''
Off-hours console login detected:
User: {user}
Source IP: {ip}
Time: {now.isoformat()}
Event: {json.dumps(event, indent=2)}

This may indicate compromised credentials. Please investigate immediately.
                      '''
                  )

              return {'statusCode': 200}
''',
                terraform_template=None,
                alert_severity="medium",
                alert_title="Off-Hours Console Login",
                alert_description_template=(
                    "User {user} logged into AWS console at {timestamp}, "
                    "which is outside normal business hours ({business_hours}). "
                    "Source IP: {source_ip}."
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
            estimated_false_positive_rate="medium",
            false_positive_tuning=(
                "Create exceptions for on-call personnel and users in different timezones. "
                "Consider using a learning period to establish baseline patterns."
            ),
            detection_coverage="30% - catches credential use from different time zones",
            evasion_considerations="Attackers aware of business hours may time their access accordingly",
            implementation_effort="medium",
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
                "for the first time, which may indicate credential compromise or privilege abuse."
            ),
            detection_type="cloudwatch_query",
            aws_service="cloudwatch",
            implementation=DetectionImplementation(
                query='''
-- First-time caller of sensitive APIs (run daily)
fields @timestamp, userIdentity.arn as user, eventSource, eventName, sourceIPAddress
| filter eventSource in [
    "iam.amazonaws.com",
    "kms.amazonaws.com",
    "secretsmanager.amazonaws.com",
    "sts.amazonaws.com"
  ]
| filter eventName in [
    "CreateUser", "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy",
    "CreateKey", "Decrypt", "GenerateDataKey",
    "GetSecretValue", "CreateSecret",
    "AssumeRole", "GetSessionToken"
  ]
| stats count(*) as call_count,
        earliest(@timestamp) as first_seen,
        latest(@timestamp) as last_seen
  by user, eventName
| filter call_count = 1
  and first_seen > ago(24h)
| sort first_seen desc
''',
                event_pattern=None,
                config_rule=None,
                guardduty_finding_types=None,
                cloudformation_template=None,
                terraform_template=None,
                alert_severity="medium",
                alert_title="First-Time Sensitive API Call",
                alert_description_template=(
                    "User {user} called {eventName} for the first time. "
                    "This is a sensitive API that could indicate credential compromise "
                    "if the user doesn't normally perform this action."
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
            estimated_false_positive_rate="medium",
            false_positive_tuning=(
                "Build a baseline of normal API usage per user over 30 days. "
                "Exclude service accounts and automation roles."
            ),
            detection_coverage="50% - catches new activity patterns",
            evasion_considerations="Attackers may gradually expand API usage or use existing patterns",
            implementation_effort="medium",
            implementation_time="2-3 hours",
            estimated_monthly_cost="$10-30",
            prerequisites=["CloudTrail enabled", "Baseline period for comparison"]
        )
    ],

    recommended_order=[
        "t1078004-guardduty",      # Enable managed detection first
        "t1078004-impossible-travel",  # Then add geographic anomaly detection
        "t1078004-off-hours",      # Then time-based detection
        "t1078004-first-time-api"  # Finally, behavioural analysis
    ],
    total_effort_hours=6.0,
    coverage_improvement="+25% improvement for Credential Access tactic",
    last_updated="2025-12-19",
    version="1.0",
    author="Security Threats Agent"
)
```

---

### Step 5: Priority Technique Coverage

Based on real-world attack trends and cloud security incidents, prioritise templates for:

#### Tier 1: Critical (Must Have) - 10 Techniques

| Technique ID | Name | Why Critical |
|--------------|------|--------------|
| T1078.004 | Cloud Accounts | #1 initial access vector in cloud breaches |
| T1110 | Brute Force | Common credential attack method |
| T1562.001 | Disable Security Tools | Attackers disable logging/monitoring first |
| T1530 | Data from Cloud Storage | S3 bucket breaches are epidemic |
| T1098 | Account Manipulation | Persistence via IAM changes |
| T1136.003 | Create Cloud Account | Persistence via new accounts |
| T1537 | Transfer to Cloud Account | Data exfiltration method |
| T1552.001 | Credentials in Files | Secrets in code/config |
| T1190 | Exploit Public-Facing App | Initial access via vulnerable apps |
| T1059.009 | Cloud API | Execution via cloud APIs |

#### Tier 2: High Priority - 15 Techniques

| Technique ID | Name |
|--------------|------|
| T1578 | Modify Cloud Compute Infrastructure |
| T1578.002 | Create Cloud Instance |
| T1496 | Resource Hijacking (Cryptomining) |
| T1040 | Network Sniffing |
| T1087.004 | Cloud Account Discovery |
| T1069.003 | Cloud Groups Discovery |
| T1580 | Cloud Infrastructure Discovery |
| T1526 | Cloud Service Discovery |
| T1538 | Cloud Service Dashboard |
| T1213 | Data from Information Repositories |
| T1119 | Automated Collection |
| T1074.002 | Remote Data Staging |
| T1048 | Exfiltration Over Alternative Protocol |
| T1567 | Exfiltration Over Web Service |
| T1486 | Data Encrypted for Impact |

#### Tier 3: Medium Priority - 20+ Techniques

Remaining cloud-relevant techniques...

---

### Step 6: Implementation Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    REMEDIATION ENGINE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌───────────────────┐    ┌───────────────────┐                │
│  │ Template Library  │    │ Technique Context │                │
│  │ (JSON/YAML files) │    │ Database          │                │
│  └─────────┬─────────┘    └─────────┬─────────┘                │
│            │                        │                           │
│            ▼                        ▼                           │
│  ┌─────────────────────────────────────────────┐               │
│  │         Template Resolver Service            │               │
│  │  • Match technique_id to template           │               │
│  │  • Enrich with threat intelligence          │               │
│  │  • Customise for account context            │               │
│  └─────────────────────┬───────────────────────┘               │
│                        │                                        │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────┐               │
│  │         Recommendation Generator            │               │
│  │  • Order by implementation priority         │               │
│  │  • Calculate effort estimates               │               │
│  │  • Generate IaC templates                   │               │
│  └─────────────────────┬───────────────────────┘               │
│                        │                                        │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────┐               │
│  │              API Response                    │               │
│  │  GET /gaps/{gap_id}/recommendations          │               │
│  │  Returns: DetailedRemediationResponse       │               │
│  └─────────────────────────────────────────────┘               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Output Artefacts

### 1. Remediation Template Library
**Location:** `backend/app/data/remediation_templates/`
**Files:**
- `t1078_004_cloud_accounts.yaml`
- `t1110_brute_force.yaml`
- `t1562_001_disable_security_tools.yaml`
- ... (one file per technique)

### 2. Template Schema
**File:** `backend/app/schemas/remediation.py`

### 3. Template Resolver Service
**File:** `backend/app/services/remediation_service.py`

### 4. Enhanced Gap API
**File:** `backend/app/api/routes/gaps.py`
**Endpoints:**
- `GET /gaps` - List all gaps with filtering
- `GET /gaps/{gap_id}` - Get gap details
- `GET /gaps/{gap_id}/recommendations` - Get detailed remediation guidance
- `PUT /gaps/{gap_id}/status` - Update gap status

### 5. Threat Intelligence Integration
**File:** `backend/app/services/threat_intel_service.py`
**Sources:**
- MITRE ATT&CK Navigator data
- CISA Known Exploited Vulnerabilities
- Cloud-specific threat reports

### 6. Test Cases
**Files:**
- `tests/remediation/test_templates.py`
- `tests/remediation/test_resolver.py`

---

## Validation Checklist

- [ ] All Tier 1 techniques have complete templates
- [ ] Templates include real, tested detection queries
- [ ] CloudFormation/Terraform templates are valid and deployable
- [ ] Threat context is accurate and up-to-date
- [ ] False positive rates are realistic estimates
- [ ] Implementation effort estimates are validated
- [ ] API endpoints return properly formatted responses
- [ ] Templates are version controlled and auditable

---

## Chain-of-Thought Summary

For each gap, the remediation engine should reason:

```
1. IDENTIFY: What technique is uncovered?
   → T1078.004 - Valid Accounts: Cloud Accounts

2. CONTEXTUALISE: Why is this dangerous for THIS account?
   → Account has 50 IAM users, no MFA enforcement, stores PII
   → Recent campaigns (Scattered Spider) actively targeting similar orgs

3. PRIORITISE: What's the best detection approach?
   → GuardDuty provides immediate coverage with minimal effort
   → CloudWatch query adds impossible travel detection
   → EventBridge provides real-time alerting

4. IMPLEMENT: What exact steps should they take?
   → Step 1: Enable GuardDuty (30 min, $4/month)
   → Step 2: Deploy CloudWatch query (2 hours, $10/month)
   → Step 3: Configure EventBridge rule (1 hour, $2/month)

5. VALIDATE: How will they know it's working?
   → Test with login from VPN in different region
   → Verify alerts are received within 15 minutes
   → Baseline false positive rate over 1 week
```

---

## Next Agent

This agent's output feeds into:
- **07-UI-DESIGN-AGENT.md** - Display detailed recommendations in UI
- **Analysis Pipeline** - Integrate templates into gap analysis

Provide downstream consumers with:
- Template schema documentation
- API response formats
- Example rendered recommendations

---

**END OF SECURITY THREATS AGENT**
