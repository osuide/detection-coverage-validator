# Remediation Template Audit Report

**Audit Date:** 26 December 2025
**Auditor:** ReAct Methodology with Parallel Agents
**Templates Audited:** 262
**Patterns Validated:** REMEDIATION_TEMPLATE_PATTERNS.md (v1.4)

---

## Executive Summary

| Pattern | Compliance | Issues Found | Priority |
|---------|------------|--------------|----------|
| EventBridge DLQ SQS Queue Policy | 35% (22/63) | **41 templates** | CRITICAL |
| EventBridge DLQ and Retry | 35% (62/177) | **115 templates** | HIGH |
| Terraform Provider Pinning | 0% (0/13) | **13 templates** | HIGH |
| IAM Confused-Deputy Mitigation | 80% (28/35) | **7 templates** | HIGH |
| GuardDuty Finding Types | Unknown | **60+ templates** with non-standard types | MEDIUM |
| SNS Topic Policy Scoping | 99% (258/259) | **1 template** | LOW |
| CloudWatch treat_missing_data | 99.6% (235/236) | **1 template** + 1 duplicate | LOW |

---

## Critical Findings

### Pattern 6a: EventBridge DLQ SQS Queue Policy (CRITICAL)

**Risk:** Without the SQS queue policy, EventBridge cannot deliver failed events to the DLQ. Events are silently lost with no error in Terraform plan/apply.

**Reference:** [AWS EventBridge DLQ Documentation](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html)

**Templates Missing SQS Queue Policy (41):**
```
t1003_credential_dumping.py
t1008_fallback_channels.py
t1011_exfil_other_network.py
t1020_automated_exfiltration.py
t1021_007_cloud_services.py
t1021_remote_services.py
t1027_obfuscated_files.py
t1029_scheduled_transfer.py
t1030_data_transfer_size_limits.py
t1036_masquerading.py
t1039_data_network_shared_drive.py
t1040_network_sniffing.py
t1046_network_service_discovery.py
t1047_wmi.py
t1053_scheduled_task.py
t1055_process_injection.py
t1056_input_capture.py
t1078_004_cloud_accounts.py
t1078_valid_accounts.py
t1098_001_additional_cloud_credentials.py
t1098_account_manipulation.py
t1110_brute_force.py
t1111_mfa_interception.py
t1112_modify_registry.py
t1113_screen_capture.py
t1136_003_create_cloud_account.py
t1140_deobfuscate_decode.py
t1176_browser_extensions.py
t1187_forced_authentication.py
t1190_exploit_public_facing_app.py
t1204_user_execution.py
t1530_data_from_cloud_storage.py
t1537_transfer_data_cloud_account.py
t1550_001_app_access_token.py
t1552_005_cloud_instance_metadata.py
t1556_modify_auth_process.py
t1560_archive_collected_data.py
t1562_001_disable_security_tools.py
t1562_008_disable_cloud_logs.py
t1562_impair_defenses.py
t1566_phishing.py
t1595_active_scanning.py
```

**Required Fix:**
```hcl
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
      values   = [aws_cloudwatch_event_rule.detection.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_dlq" {
  queue_url = aws_sqs_queue.dlq.url
  policy    = data.aws_iam_policy_document.eventbridge_dlq_policy.json
}
```

---

### Pattern 6b: EventBridge DLQ and Retry Policy (HIGH)

**Risk:** Without DLQ and retry, transient failures result in permanent event loss.

**Statistics:**
- Templates with EventBridge targets: 177
- Templates with both DLQ + retry: 62 (35%)
- Templates missing both: 114 (64%)
- Templates missing only retry: 1

**First 20 Templates Missing Both:**
```
t1012_query_registry.py
t1027_006_html_smuggling.py
t1049_network_connections_discovery.py
t1052_exfil_physical_medium.py
t1071_001_web_protocols.py
t1071_003_mail_protocols.py
t1071_004_dns.py
t1080_taint_shared_content.py
t1087_account_discovery.py
t1090_003_multi_hop_proxy.py
t1090_proxy.py
t1091_removable_media.py
t1095_non_app_layer_protocol.py
t1098_003_additional_cloud_roles.py
t1098_005_device_registration.py
t1102_002_bidirectional_communication.py
t1102_web_service.py
t1104_multi_stage_channels.py
t1105_ingress_tool_transfer.py
t1106_native_api.py
(+ 94 more)
```

---

### Pattern 8: Terraform Provider Pinning (HIGH)

**Risk:** Supply-chain drift and deployment failures from uncontrolled provider versions.

**Templates Using archive_file Without Provider Declaration (13):**
```
t1059_009_cloud_api.py
t1078_004_cloud_accounts.py
t1078_valid_accounts.py
t1098_001_additional_cloud_credentials.py
t1110_001_password_guessing.py
t1136_003_create_cloud_account.py
t1486_data_encrypted_for_impact.py
t1530_data_from_cloud_storage.py
t1538_cloud_service_dashboard.py
t1550_001_app_access_token.py
t1555_006_cloud_secrets.py
t1648_serverless_execution.py
t1651_cloud_admin_command.py
```

**Required Fix:**
```hcl
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}
```

---

### Pattern 3: IAM Confused-Deputy Mitigation (HIGH)

**Risk:** IAM roles can be assumed by unintended services (confused-deputy attack).

**Templates Missing Conditions (7):**
```
t1078_001_default_accounts.py
t1564_hide_artifacts.py
t1565_001_stored_data_manipulation.py
t1571_non_standard_port.py
t1573_encrypted_channel.py
t1596_search_open_technical_databases.py
t1648_serverless_execution.py (partial - missing aws:SourceArn)
```

---

## Medium Priority Findings

### GuardDuty Finding Type Validation (MEDIUM)

**Risk:** Non-standard finding types will never trigger, creating false sense of coverage.

**Summary:**
- 74 templates with `guardduty_finding_types` declarations
- 153 distinct finding types referenced
- **60+ non-standard finding types** identified

**Non-Standard Categories Found:**
| Category | Count | Status |
|----------|-------|--------|
| Execution:* | 60+ | NOT in AWS GuardDuty |
| Behavior:* | 9 | NOT in AWS GuardDuty |
| DefenseEvasion:* | 12+ | NOT in AWS GuardDuty |
| PrivilegeEscalation:* | 8+ | NOT in AWS GuardDuty |
| Discovery:* | 5+ | NOT in AWS GuardDuty |
| Stealth:* | 4+ | NOT in AWS GuardDuty |

**Malformed Finding Type:**
- `Defense Evasion:Runtime/ProcessInjectionAttempt` has **space** instead of camelCase

**Action Required:** Validate all GuardDuty finding types against official AWS documentation.

---

## Low Priority Findings

### Pattern 5: SNS Topic Policy Scoping (LOW)

**Status:** 99% compliant (258/259 templates)

**Templates with AWS:SourceAccount:** 258
**Templates missing AWS:SourceAccount:** 1

**Templates missing aws:SourceArn for EventBridge scoping:**
- t1559_inter_process_comm.py (confirmed)
- Several others need review

---

### Pattern 7: CloudWatch treat_missing_data (LOW)

**Status:** 99.6% compliant

**Terraform:**
- With `aws_cloudwatch_metric_alarm`: 236
- With `treat_missing_data = "notBreaching"`: 235
- Missing: 1 template

**CloudFormation:**
- With `Type: AWS::CloudWatch::Alarm`: 220
- With `TreatMissingData: notBreaching`: 219
- Missing: 1 template

**Bug Found:**
- `t1556_009_conditional_access_policies.py` has DUPLICATE `treat_missing_data` on lines 178 and 181

---

## Remediation Priority

### Immediate Action (Week 1)
1. Add SQS queue policy to 41 templates with DLQ (Pattern 6a - CRITICAL)
2. Add `hashicorp/archive` provider declaration to 13 templates (Pattern 8)
3. Fix the malformed GuardDuty finding type with space

### Short-Term (Week 2-3)
1. Add DLQ + retry to 114 EventBridge templates (Pattern 6b)
2. Add confused-deputy conditions to 7 IAM role templates (Pattern 3)
3. Review and validate GuardDuty finding types against AWS documentation

### Ongoing
1. Update template review checklist to include all patterns
2. Add automated validation in CI/CD pipeline

---

## Validation Sources

- [AWS EventBridge DLQ Documentation](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html)
- [Terraform Syntax Documentation](https://developer.hashicorp.com/terraform/language/syntax/configuration)
- [Terraform jsonencode Function](https://developer.hashicorp.com/terraform/language/functions/jsonencode)
- AWS GuardDuty Finding Types Documentation

---

## Appendix: Compliant Template Examples

**Fully Compliant Templates (all patterns):**
- t1059_command_scripting.py
- t1098_004_ssh_authorized_keys.py
- t1609_container_admin_command.py
- t1610_deploy_container.py
- t1612_build_image_on_host.py
- t1651_cloud_admin_command.py

Use these as reference when fixing non-compliant templates.

---

**Report Generated:** 26 December 2025
**Next Audit Due:** 26 January 2026
