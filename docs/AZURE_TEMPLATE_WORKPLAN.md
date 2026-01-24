# Azure Remediation Template Workplan

**Document Version:** 1.1
**Created:** 2026-01-24
**Updated:** 2026-01-24
**Status:** Week 4 Complete - Week 5 Pending

## Progress Summary

| Week | Focus | Status | Commit |
|------|-------|--------|--------|
| Week 1 | Create 5 missing templates | ✅ Complete | 33e66fc |
| Week 2 | Identity/Access KQL (7 techniques) | ✅ Complete | 7875647 |
| Week 3 | Defence Evasion/Credential Access KQL (8 techniques) | ✅ Complete | d1e508d |
| Week 4 | Remaining KQL (15 techniques) | ✅ Complete | e10dc69 |
| Week 5 | Validation and testing | ⏳ Pending | - |

### Week 4 Details (Completed)
All 15 remaining templates updated with Azure KQL queries:

**Lateral Movement/Discovery:**
- **T1021** - Remote Services (RDP/SSH/VNC/WinRM via Entra ID and Defender)
- **T1090** - Proxy (Application Gateway, Front Door, tunnel detection)
- **T1133** - External Remote Services (VPN, Bastion, JIT access)
- **T1199** - Trusted Relationship (Cross-tenant, B2B guest, partner access)
- **T1557** - Adversary-in-the-Middle (ARP spoofing, network interception)

**Execution:**
- **T1059** - Command and Scripting (VM Run Command, Automation, Cloud Shell)
- **T1190** - Exploit Public-Facing (WAF, App Service, web attack detection)
- **T1203** - Client Exploitation (Defender for Endpoint process monitoring)

**Impact/Resource:**
- **T1496** - Resource Hijacking (Cryptomining, GPU VMs, high CPU detection)
- **T1498** - Network DoS (DDoS Protection, Azure Firewall, NSG analysis)
- **T1499** - Endpoint DoS (App Service, API Management, Cosmos DB throttling)

**Container/Credential:**
- **T1525** - Implant Internal Image (ACR push/pull and vulnerability)
- **T1550.001** - App Access Token (Token theft, replay, OAuth monitoring)
- **T1610** - Deploy Container (ACI, AKS, container deployment tracking)
- **T1611** - Escape to Host (Privileged containers and escape attempts)

### Week 3 Details (Completed)
All 8 Defence Evasion and Credential Access templates updated with Azure KQL queries:

**Defence Evasion (T1562.x):**
- **T1562.001** - Impair Defences: Disable/Modify Tools (Defender for Cloud disable, Sentinel rules delete)
- **T1562.007** - Disable/Modify Cloud Firewall (NSG, Azure Firewall, WAF modifications)
- **T1562.008** - Disable Cloud Logs (Diagnostic settings, Activity Log, Log Analytics)

**Network/Credential Access:**
- **T1040** - Network Sniffing (Network Watcher, packet captures, VNet TAP)
- **T1552** - Unsecured Credentials (Key Vault bulk access, App Configuration)
- **T1552.001** - Credentials in Files (Key Vault secrets, storage credential files)
- **T1552.007** - Container API (AKS secrets access, Container Registry)
- **T1555.006** - Cloud Secrets (Key Vault operations, multi-vault access patterns)

### Week 2 Details (Completed)
All 7 Identity/Access templates updated with Azure KQL queries:
- **T1078.004** - Valid Accounts: Cloud Accounts (SigninLogs risky sign-in detection, impossible travel)
- **T1110** - Brute Force (SigninLogs failed auth detection, password spray)
- **T1098.003** - Additional Cloud Roles (AuditLogs privileged role assignment detection)
- **T1068** - Exploitation for Privilege Escalation (SecurityAlert priv esc detection)
- **T1204** - User Execution (Cloud Shell and portal execution detection)
- **T1204.002** - Malicious File (Defender for Endpoint file execution alerts)
- **T1204.003** - Malicious Image (Container/VM image deployment detection)

## Executive Summary

The A13E Detection Coverage Validator has **critical gaps** in Azure implementation templates. While 100% of templates have Azure Terraform infrastructure defined, only **30.2%** have functional Azure KQL (Kusto Query Language) detection queries.

### Current State

| Metric | Count | Percentage |
|--------|-------|-----------|
| Unique Azure MITRE techniques | 48 | - |
| Templates that exist | 43 | 89.6% |
| Templates with KQL queries | 13 | 30.2% |
| Templates with Terraform only | 30 | 69.8% |
| Missing templates entirely | 5 | 10.4% |

---

## Part 1: Missing Remediation Templates (5 Techniques)

These techniques have **no remediation template file** and need to be created from scratch.

### T1021.001 - Remote Services: Remote Desktop Protocol

**Priority:** HIGH
**Azure Detection Method:** Microsoft Defender for Servers, Network Security Groups, Azure Firewall

**KQL Query Requirements:**
```kusto
// RDP Brute Force Detection
SecurityEvent
| where EventID == 4625
| where LogonType == 10  // RemoteInteractive
| summarize FailedAttempts = count() by SourceIP = IpAddress, TargetAccount = Account, Computer
| where FailedAttempts > 5
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | where LogonType == 10
) on SourceIP, TargetAccount
```

**Azure Documentation:**
- [Monitor RDP brute force attacks](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Just-in-time VM access](https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-usage)

---

### T1021.004 - Remote Services: SSH

**Priority:** HIGH
**Azure Detection Method:** Microsoft Defender for Servers, Syslog integration, Azure Bastion

**KQL Query Requirements:**
```kusto
// SSH Brute Force Detection
Syslog
| where Facility == "auth" or Facility == "authpriv"
| where SyslogMessage contains "Failed password" or SyslogMessage contains "Invalid user"
| parse SyslogMessage with * "from " SourceIP " port" *
| summarize FailedAttempts = count() by SourceIP, Computer, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
```

**Azure Documentation:**
- [Syslog data collection](https://learn.microsoft.com/en-us/azure/sentinel/connect-syslog)
- [Linux security alerts](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)

---

### T1059.007 - Command and Scripting Interpreter: JavaScript

**Priority:** MEDIUM
**Azure Detection Method:** Microsoft Defender for App Service, Application Insights

**KQL Query Requirements:**
```kusto
// Suspicious JavaScript Execution in App Service
AppServiceHTTPLogs
| where TimeGenerated > ago(24h)
| where CsUriStem contains ".js" or CsUriQuery contains "script"
| where ScStatus >= 200 and ScStatus < 300
| summarize count() by CsHost, CsUriStem, CIp
| where count_ > 100
```

**Azure Documentation:**
- [Defender for App Service](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-app-service-introduction)
- [App Service diagnostics](https://learn.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs)

---

### T1505.003 - Server Software Component: Web Shell

**Priority:** HIGH
**Azure Detection Method:** Microsoft Defender for Servers, Azure Web Application Firewall

**KQL Query Requirements:**
```kusto
// Web Shell Detection
W3CIISLog
| where TimeGenerated > ago(24h)
| where csUriStem matches regex @"\.(aspx|asp|php|jsp|jspx)$"
| where csUriQuery contains "cmd=" or csUriQuery contains "exec=" or csUriQuery contains "shell="
| project TimeGenerated, sSiteName, csUriStem, csUriQuery, cIP, csUserAgent
```

**Azure Documentation:**
- [Web shell detection](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference#alerts-windows)
- [WAF custom rules](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/custom-waf-rules-overview)

---

### T1552.004 - Unsecured Credentials: Private Keys

**Priority:** HIGH
**Azure Detection Method:** Azure Key Vault, Defender for Cloud, Azure Policy

**KQL Query Requirements:**
```kusto
// Private Key Access Detection
AzureActivity
| where OperationNameValue contains "Microsoft.KeyVault/vaults/keys/read"
    or OperationNameValue contains "Microsoft.KeyVault/vaults/secrets/read"
| where ActivityStatusValue == "Success"
| summarize AccessCount = count() by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where AccessCount > 50  // Anomaly threshold
```

**Azure Documentation:**
- [Key Vault monitoring](https://learn.microsoft.com/en-us/azure/key-vault/general/logging)
- [Defender for Key Vault](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-key-vault-introduction)

---

## Part 2: Templates Missing KQL Queries (30 Techniques)

These templates exist but have **empty Azure KQL queries**. Each needs a KQL query added.

### Priority 1: Identity & Access Management (7 techniques)

| Technique | Name | Azure Data Source | Effort |
|-----------|------|-------------------|--------|
| T1068 | Exploitation for Privilege Escalation | SecurityEvent, AzureDiagnostics | Medium |
| T1078.004 | Valid Accounts: Cloud Accounts | SigninLogs, AuditLogs | Low |
| T1098.003 | Additional Cloud Roles | AuditLogs | Low |
| T1110 | Brute Force | SigninLogs | Low |
| T1204 | User Execution | SecurityEvent | Medium |
| T1204.002 | Malicious File | SecurityEvent, Defender alerts | Medium |
| T1204.003 | Malicious Image | ContainerRegistryLoginEvents | Medium |

**Sample KQL for T1078.004 (Valid Accounts):**
```kusto
// Suspicious Cloud Account Usage
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0  // Successful sign-in
| where RiskLevelDuringSignIn in ("high", "medium")
| extend City = tostring(LocationDetails.city)
| extend Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, City, Country, RiskLevelDuringSignIn
| order by RiskLevelDuringSignIn desc, TimeGenerated desc
```

**Sample KQL for T1110 (Brute Force):**
```kusto
// Brute Force Attack Detection
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == 50126  // Invalid username or password
| summarize
    FailedAttempts = count(),
    DistinctUsers = dcount(UserPrincipalName),
    Accounts = make_set(UserPrincipalName, 10)
    by IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| order by FailedAttempts desc
```

---

### Priority 2: Defence Evasion (3 techniques)

| Technique | Name | Azure Data Source | Effort |
|-----------|------|-------------------|--------|
| T1562.001 | Disable or Modify Tools | AzureActivity, AuditLogs | Medium |
| T1562.007 | Disable or Modify Cloud Firewall | AzureActivity | Low |
| T1562.008 | Disable Cloud Logs | AzureActivity, AuditLogs | Low |

**Sample KQL for T1562.008 (Disable Cloud Logs):**
```kusto
// Diagnostic Settings Modification Detection
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue contains "Microsoft.Insights/diagnosticSettings"
| where ActivityStatusValue == "Success"
| where OperationNameValue contains "delete" or Properties contains "\"enabled\":false"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceGroup, Resource
| order by TimeGenerated desc
```

---

### Priority 3: Credential Access (5 techniques)

| Technique | Name | Azure Data Source | Effort |
|-----------|------|-------------------|--------|
| T1040 | Network Sniffing | AzureNetworkAnalytics_CL | High |
| T1552 | Unsecured Credentials | AzureActivity, SecurityEvent | Medium |
| T1552.001 | Credentials in Files | SecurityEvent | Medium |
| T1552.007 | Container API | ContainerLog | Medium |
| T1555.006 | Cloud Secrets | AzureDiagnostics (Key Vault) | Low |

**Sample KQL for T1555.006 (Cloud Secrets):**
```kusto
// Suspicious Key Vault Secret Access
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretGet"
| where TimeGenerated > ago(24h)
| summarize
    AccessCount = count(),
    UniqueSecrets = dcount(ResultDescription)
    by CallerIPAddress, identity_claim_upn_s, bin(TimeGenerated, 1h)
| where AccessCount > 20  // Anomalous access threshold
| order by AccessCount desc
```

---

### Priority 4: Lateral Movement & Discovery (5 techniques)

| Technique | Name | Azure Data Source | Effort |
|-----------|------|-------------------|--------|
| T1021 | Remote Services | SigninLogs, SecurityEvent | Medium |
| T1090 | Proxy | AzureNetworkAnalytics_CL | High |
| T1133 | External Remote Services | SigninLogs | Low |
| T1199 | Trusted Relationship | AuditLogs, ServicePrincipalSignInLogs | Medium |
| T1557 | Adversary-in-the-Middle | AzureNetworkAnalytics_CL | High |

**Sample KQL for T1133 (External Remote Services):**
```kusto
// External Remote Service Access
SigninLogs
| where TimeGenerated > ago(24h)
| where AppDisplayName in ("Windows Sign In", "Microsoft Remote Desktop", "Azure Portal")
| where ResultType == 0
| where NetworkLocationDetails !contains "Trusted"
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize LoginCount = count() by UserPrincipalName, IPAddress, Country, AppDisplayName
| where LoginCount > 5
```

---

### Priority 5: Collection & Exfiltration (3 techniques)

| Technique | Name | Azure Data Source | Effort |
|-----------|------|-------------------|--------|
| T1498 | Network Denial of Service | AzureNetworkAnalytics_CL | High |
| T1499 | Endpoint Denial of Service | AzureMetrics | Medium |
| T1550.001 | Application Access Token | AuditLogs | Medium |

---

### Priority 6: Execution & Container (6 techniques)

| Technique | Name | Azure Data Source | Effort |
|-----------|------|-------------------|--------|
| T1059 | Command and Scripting Interpreter | SecurityEvent | Medium |
| T1190 | Exploit Public-Facing Application | AzureActivity, AppServiceHTTPLogs | Medium |
| T1203 | Exploitation for Client Execution | SecurityEvent | High |
| T1496 | Resource Hijacking | AzureMetrics, AzureActivity | Medium |
| T1525 | Implant Internal Image | ContainerRegistryLoginEvents | Medium |
| T1610 | Deploy Container | AzureActivity, KubeEvents | Medium |
| T1611 | Escape to Host | KubePodInventory, SecurityEvent | High |

---

## Part 3: Azure-Specific Detection Capabilities

### Microsoft Defender for Cloud Alerts

The following Defender alert types should be referenced in templates:

| Alert Type | MITRE Techniques | Priority |
|------------|------------------|----------|
| `VM.Windows_SuspiciousAccountCreation` | T1136 | High |
| `VM.Windows_RDPBruteForce` | T1021.001, T1110 | High |
| `Storage.Blob_AnomalousDeletion` | T1485 | High |
| `KeyVault_SuspiciousActivity` | T1552, T1555.006 | High |
| `AKS_PrivilegedContainer` | T1611 | High |
| `SQL_BruteForce` | T1110 | Medium |

### Entra ID Protection Signals

These should be integrated into identity-related templates:

| Risk Detection | MITRE Techniques |
|----------------|------------------|
| Unfamiliar sign-in properties | T1078.004 |
| Anonymous IP address | T1078.004 |
| Impossible travel | T1078.004 |
| Malware-linked IP | T1078.004 |
| Password spray | T1110 |
| Leaked credentials | T1552.001 |

---

## Part 4: Implementation Guidelines

### KQL Query Standards

All Azure KQL queries must follow these standards:

1. **Time scoping:** Always include `| where TimeGenerated > ago(Xh/d)`
2. **Performance:** Apply filters early in the query pipeline
3. **Projections:** Use `project` to limit output columns
4. **Aggregations:** Use `summarize` for pattern detection
5. **Thresholds:** Document anomaly thresholds and tuning guidance

### Terraform Template Standards

All Azure Terraform templates must include:

```hcl
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
  description = "Resource group for Log Analytics workspace"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace resource ID"
}

variable "alert_email" {
  type        = string
  description = "Email for security alerts"
}

# Location should default to uksouth for UK English consistency
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "detection" {
  location = "uksouth"
  # ... rule configuration
}
```

---

## Part 5: Validation Sources

All implementations must be validated against these authoritative sources:

### Microsoft Documentation
- [Microsoft Sentinel built-in detection rules](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-built-in)
- [Defender for Cloud alerts reference](https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference)
- [KQL reference](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)
- [Azure Monitor Logs schema](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-overview)

### MITRE CTI Sources
- [Security Stack Mappings - Azure](https://center-for-threat-informed-defense.github.io/security-stack-mappings/Azure/README.html)
- [MITRE ATT&CK Framework v18](https://attack.mitre.org/)

### Community KQL Resources
- [Bert-JanP/Hunting-Queries-Detection-Rules](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)
- [Cloud-Architekt/AzureAD-Attack-Defense](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
- [KQL Query Sources](https://kqlquery.com/posts/kql_sources/)

---

## Part 6: Effort Estimation

### Summary by Priority

| Priority | Techniques | Estimated Effort |
|----------|------------|------------------|
| P1 - Missing templates | 5 | 10-15 hours |
| P2 - Identity/Access KQL | 7 | 7-10 hours |
| P3 - Defence Evasion KQL | 3 | 3-5 hours |
| P4 - Credential Access KQL | 5 | 8-12 hours |
| P5 - Lateral Movement KQL | 5 | 8-12 hours |
| P6 - Other KQL | 10 | 15-20 hours |
| **Total** | **35** | **51-74 hours** |

### Recommended Implementation Order

1. **Week 1:** Create 5 missing template files
2. **Week 2:** Add KQL to Priority 1 (Identity/Access) - highest detection value
3. **Week 3:** Add KQL to Priority 2-3 (Defence Evasion, Credential Access)
4. **Week 4:** Add KQL to Priority 4-6 (remaining techniques)
5. **Week 5:** Validation and testing

---

## Appendix A: Complete Technique List

### Techniques with Complete Azure Implementation (13)
- T1005, T1025, T1046, T1070, T1098, T1136.003, T1485, T1490, T1528, T1530, T1548, T1562, T1567.002

### Techniques Needing KQL Only (30)
- T1021, T1040, T1059, T1068, T1078.004, T1090, T1098.003, T1110, T1133, T1190, T1199, T1203, T1204, T1204.002, T1204.003, T1496, T1498, T1499, T1525, T1550.001, T1552, T1552.001, T1552.007, T1555.006, T1557, T1562.001, T1562.007, T1562.008, T1610, T1611

### Techniques Needing Full Templates (5)
- T1021.001, T1021.004, T1059.007, T1505.003, T1552.004

---

## Appendix B: Azure Log Tables Reference

| Table | Description | Common Techniques |
|-------|-------------|-------------------|
| `SigninLogs` | Entra ID sign-in events | T1078.004, T1110, T1133 |
| `AuditLogs` | Entra ID audit events | T1098, T1136, T1562 |
| `AzureActivity` | Azure control plane events | T1562, T1580, T1578 |
| `SecurityEvent` | Windows security events | T1003, T1021, T1059 |
| `Syslog` | Linux system logs | T1021.004, T1059 |
| `AzureDiagnostics` | Azure service diagnostics | T1555.006 |
| `ContainerLog` | Kubernetes container logs | T1610, T1611 |
| `KubeEvents` | Kubernetes events | T1525, T1610 |
| `AppServiceHTTPLogs` | App Service requests | T1190, T1059.007 |

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-24 | Claude (Discovery) | Initial analysis and workplan |
