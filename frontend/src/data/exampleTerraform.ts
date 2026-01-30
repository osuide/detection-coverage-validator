/**
 * Example Terraform configuration for the Quick Scan "Try Example" button.
 *
 * Uses only literal values (no Terraform functions or references) so
 * python-hcl2 can parse it without interpolation issues.
 *
 * Designed to demonstrate meaningful MITRE ATT&CK coverage by using
 * EventBridge rules with specific CloudTrail eventName arrays (strongest
 * signal for the pattern mapper), CloudWatch log metric filters, and
 * security-keyword-rich names/descriptions.
 */
export const EXAMPLE_TERRAFORM = `# AWS Detection Coverage — Example Configuration
# Paste your own Terraform HCL to analyse your detection coverage.

# ─── Managed detection services ────────────────────────────────────

resource "aws_guardduty_detector" "main" {
  enable = true

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
}

resource "aws_securityhub_account" "main" {}

resource "aws_config_config_rule" "encrypted_volumes" {
  name = "encrypted-volumes"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
}

# ─── Initial Access / Credential Access ────────────────────────────

resource "aws_cloudwatch_event_rule" "console_signin_failure" {
  name        = "detect-console-signin-failure"
  description = "Detect failed console login attempts and brute force password guessing"

  event_pattern = <<EOF
{
  "source": ["aws.signin"],
  "detail-type": ["AWS Console Sign In via CloudTrail"],
  "detail": {
    "eventName": ["ConsoleLogin"]
  }
}
EOF
}

# ─── Persistence / Privilege Escalation ────────────────────────────

resource "aws_cloudwatch_event_rule" "iam_policy_changes" {
  name        = "detect-iam-policy-changes"
  description = "Detect IAM account manipulation, privilege escalation, and credential creation"

  event_pattern = <<EOF
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": [
      "CreateAccessKey",
      "CreateLoginProfile",
      "AttachUserPolicy",
      "AttachRolePolicy",
      "PutUserPolicy",
      "PutRolePolicy",
      "CreateRole",
      "UpdateAssumeRolePolicy",
      "AddUserToGroup",
      "CreateUser"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_rule" "sts_token_activity" {
  name        = "detect-cross-account-assume-role"
  description = "Detect cross-account trust, temporary elevated access, and session token usage"

  event_pattern = <<EOF
{
  "source": ["aws.sts"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["sts.amazonaws.com"],
    "eventName": [
      "AssumeRole",
      "AssumeRoleWithSAML",
      "AssumeRoleWithWebIdentity",
      "GetSessionToken",
      "GetFederationToken"
    ]
  }
}
EOF
}

# ─── Defense Evasion ───────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "cloudtrail_tampering" {
  name        = "detect-cloudtrail-logging-disable"
  description = "Detect CloudTrail logging being stopped, deleted, or impaired"

  event_pattern = <<EOF
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["cloudtrail.amazonaws.com"],
    "eventName": [
      "StopLogging",
      "DeleteTrail",
      "UpdateTrail",
      "PutEventSelectors"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_rule" "security_group_changes" {
  name        = "detect-security-group-firewall-changes"
  description = "Detect security group and network ACL firewall modifications"

  event_pattern = <<EOF
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": [
      "AuthorizeSecurityGroupIngress",
      "AuthorizeSecurityGroupEgress",
      "RevokeSecurityGroupIngress",
      "CreateSecurityGroup",
      "DeleteSecurityGroup"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_rule" "guardduty_defender_disable" {
  name        = "detect-security-tool-disable"
  description = "Detect disabling of GuardDuty, SecurityHub, or other security defense tools"

  event_pattern = <<EOF
{
  "source": ["aws.guardduty", "aws.securityhub"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": [
      "DeleteDetector",
      "UpdateDetector",
      "DisableSecurityHub",
      "DisableImportFindings",
      "DeleteMembers"
    ]
  }
}
EOF
}

# ─── Credential Access ─────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "secrets_access" {
  name        = "detect-secret-credential-access"
  description = "Detect access to secrets, credential stores, and parameter store"

  event_pattern = <<EOF
{
  "source": ["aws.secretsmanager"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["secretsmanager.amazonaws.com"],
    "eventName": [
      "GetSecretValue",
      "ListSecrets",
      "DescribeSecret"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_rule" "saml_federation_changes" {
  name        = "detect-saml-sso-federation-changes"
  description = "Detect SAML provider and SSO federation identity modifications"

  event_pattern = <<EOF
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": [
      "CreateSAMLProvider",
      "UpdateSAMLProvider",
      "AssumeRoleWithSAML",
      "CreateIdentityProvider"
    ]
  }
}
EOF
}

# ─── Discovery ─────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "infrastructure_discovery" {
  name        = "detect-cloud-infrastructure-discovery"
  description = "Detect enumeration of instances, VPCs, security groups, and network infrastructure"

  event_pattern = <<EOF
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": [
      "DescribeInstances",
      "DescribeSecurityGroups",
      "DescribeSubnets",
      "DescribeVpcs",
      "DescribeNetworkInterfaces"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_rule" "s3_storage_discovery" {
  name        = "detect-cloud-storage-object-discovery"
  description = "Detect S3 bucket and storage object enumeration and listing"

  event_pattern = <<EOF
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["s3.amazonaws.com"],
    "eventName": [
      "ListBuckets",
      "ListObjects",
      "ListObjectsV2",
      "GetBucketPolicy",
      "GetBucketAcl"
    ]
  }
}
EOF
}

# ─── Lateral Movement ──────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "remote_session_access" {
  name        = "detect-ssh-remote-session-access"
  description = "Detect SSH and SSM remote session lateral movement"

  event_pattern = <<EOF
{
  "source": ["aws.ssm", "aws.ec2-instance-connect"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": [
      "StartSession",
      "SendCommand",
      "SendSSHPublicKey"
    ]
  }
}
EOF
}

# ─── Collection / Exfiltration ─────────────────────────────────────

resource "aws_cloudwatch_event_rule" "s3_data_exfiltration" {
  name        = "detect-s3-public-share-exfiltration"
  description = "Detect S3 bucket policy changes enabling public access or external data transfer"

  event_pattern = <<EOF
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["s3.amazonaws.com"],
    "eventName": [
      "PutBucketPolicy",
      "PutBucketAcl",
      "DeleteBucketPolicy"
    ]
  }
}
EOF
}

# ─── Impact ────────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "data_destruction" {
  name        = "detect-data-destruction-terminate"
  description = "Detect deletion of critical resources, snapshots, and backups"

  event_pattern = <<EOF
{
  "source": ["aws.ec2", "aws.rds"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": [
      "TerminateInstances",
      "DeleteSnapshot",
      "DeleteDBSnapshot",
      "DeleteDBInstance",
      "DeleteVolume",
      "DeleteBucket"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_rule" "account_lockout" {
  name        = "detect-account-access-removal"
  description = "Detect IAM user and role deletion, access key revocation, and account lockout"

  event_pattern = <<EOF
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": [
      "DeleteUser",
      "DeleteRole",
      "DeleteAccessKey",
      "DeactivateMFADevice",
      "RemoveUserFromGroup"
    ]
  }
}
EOF
}

# ─── CloudWatch Log Metric Filters ────────────────────────────────

resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  name           = "detect-unauthorized-api-calls"
  log_group_name = "/aws/cloudtrail/logs"
  pattern        = "{ ($.errorCode = UnauthorizedAccess) || ($.errorCode = AccessDenied) }"

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "SecurityMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "root_account_usage" {
  name           = "detect-root-account-login"
  log_group_name = "/aws/cloudtrail/logs"
  pattern        = "{ ($.userIdentity.type = Root) && ($.userIdentity.invokedBy NOT EXISTS) }"

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "SecurityMetrics"
    value     = "1"
  }
}

# ─── Execution ─────────────────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "lambda_serverless_execution" {
  name        = "detect-serverless-lambda-execution-changes"
  description = "Detect Lambda function creation, modification, and serverless execution"

  event_pattern = <<EOF
{
  "source": ["aws.lambda"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["lambda.amazonaws.com"],
    "eventName": [
      "CreateFunction",
      "UpdateFunctionCode",
      "InvokeFunction",
      "CreateEventSourceMapping"
    ]
  }
}
EOF
}

# ─── Notification ──────────────────────────────────────────────────

resource "aws_sns_topic" "security_alerts" {
  name              = "security-alerts"
  kms_master_key_id = "alias/aws/sns"
}
`
