# MITRE ATT&CK Cloud Technique Priority List

**Last Updated**: 2025-12-19
**Sources**:
- [Unit 42 Cloud Security Alert Trends 2025](https://unit42.paloaltonetworks.com/2025-cloud-security-alert-trends/)
- [Cloud Security Alliance Top Threats 2025](https://cloudsecurityalliance.org/artifacts/top-threats-to-cloud-computing-2025)
- [Google Cloud Threat Horizons H2 2025](https://services.google.com/fh/files/misc/cloud_threat_horizons_report_h22025.pdf)
- [Datadog State of Cloud Security](https://www.datadoghq.com/state-of-cloud-security/)

## Priority Criteria

Based on 2024/2025 threat intelligence:
1. **60% of cloud threats target identity/initial access** - credential abuse is #1
2. **388% increase in cloud alerts** in 2024
3. **45% increase in data exfiltration** via snapshots (Nov 2024)
4. **305% increase in suspicious storage downloads**
5. **96% of incidents in AWS** (Expel 2023 data)

## Priority Tiers

### TIER 1: CRITICAL (Immediate - Most Exploited)
*These techniques were involved in major 2024 breaches (Snowflake, AWS .env attacks)*

| # | Technique | Name | Reason |
|---|-----------|------|--------|
| 1 | T1078.004 | Valid Accounts: Cloud Accounts | ✅ DONE - #1 attack vector, 60% of threats |
| 2 | T1552.001 | Unsecured Credentials: Credentials in Files | ✅ DONE - .env file attacks hit 230M AWS environments |
| 3 | T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | ✅ DONE - IMDS attacks for credential theft |
| 4 | T1098 | Account Manipulation | ✅ DONE - Persistence via IAM changes |
| 5 | T1110 | Brute Force | ✅ DONE - Password spraying common |
| 6 | T1528 | Steal Application Access Token | ✅ DONE - OAuth/token theft in Snowflake breach |
| 7 | T1530 | Data from Cloud Storage | ✅ DONE - S3/GCS data theft |
| 8 | T1537 | Transfer Data to Cloud Account | ✅ DONE - Cross-account exfiltration |
| 9 | T1562.001 | Impair Defences: Disable or Modify Tools | ✅ DONE - Disabling logging/GuardDuty |
| 10 | T1562.008 | Impair Defences: Disable or Modify Cloud Logs | ✅ DONE - CloudTrail/Audit Log tampering |

### TIER 2: HIGH (Week 1 - Active Exploitation)
*Commonly seen in cloud incident response*

| # | Technique | Name | Reason |
|---|-----------|------|--------|
| 11 | T1098.001 | Account Manipulation: Additional Cloud Credentials | ✅ DONE - Access key creation for persistence |
| 12 | T1098.003 | Account Manipulation: Additional Cloud Roles | ✅ DONE - Role/policy escalation |
| 13 | T1136.003 | Create Account: Cloud Account | ✅ DONE - Shadow admin creation |
| 14 | T1087.004 | Account Discovery: Cloud Account | ✅ DONE - IAM enumeration |
| 15 | T1069.003 | Permission Groups Discovery: Cloud Groups | ✅ DONE - Role/group enumeration |
| 16 | T1580 | Cloud Infrastructure Discovery | ✅ DONE - Resource enumeration |
| 17 | T1526 | Cloud Service Discovery | Service enumeration |
| 18 | T1619 | Cloud Storage Object Discovery | Bucket/object listing |
| 19 | T1578.001 | Modify Cloud Compute: Create Snapshot | ✅ DONE - Snapshot exfiltration (45% increase) |
| 20 | T1578.002 | Modify Cloud Compute: Create Cloud Instance | Cryptomining/persistence |

### TIER 3: HIGH-MEDIUM (Week 2 - Defence Evasion Focus)
*Common in sophisticated attacks*

| # | Technique | Name | Reason |
|---|-----------|------|--------|
| 21 | T1535 | Unused/Unsupported Cloud Regions | Evasion via obscure regions |
| 22 | T1550.001 | Use Alternate Auth: Application Access Token | Token replay attacks |
| 23 | T1555.006 | Credentials from Password Stores: Cloud Secrets | Secrets Manager theft |
| 24 | T1606.002 | Forge Web Credentials: SAML Tokens | Golden SAML attacks |
| 25 | T1621 | MFA Request Generation | MFA fatigue/push bombing |
| 26 | T1556.006 | Modify Auth Process: MFA | MFA bypass/manipulation |
| 27 | T1578.003 | Modify Cloud Compute: Delete Cloud Instance | Evidence destruction |
| 28 | T1578.005 | Modify Cloud Compute: Modify Configurations | Security group changes |
| 29 | T1562.007 | Impair Defences: Disable Cloud Firewall | Security group/firewall disable |
| 30 | T1070.008 | Indicator Removal: Clear Mailbox Data | Evidence destruction |

### TIER 4: MEDIUM (Week 3 - Execution & Lateral Movement)
*Serverless and cloud-native attacks*

| # | Technique | Name | Reason |
|---|-----------|------|--------|
| 31 | T1648 | Serverless Execution | Lambda/Cloud Functions abuse |
| 32 | T1651 | Cloud Administration Command | SSM/Cloud Shell abuse |
| 33 | T1059.009 | Command and Scripting: Cloud API | API abuse |
| 34 | T1204.003 | User Execution: Malicious Image | Container image attacks |
| 35 | T1525 | Implant Internal Image | Backdoored AMI/images |
| 36 | T1021.007 | Remote Services: Cloud Services | Cloud service lateral movement |
| 37 | T1021.008 | Remote Services: Direct Cloud VM Connections | Serial console/SSM abuse |
| 38 | T1496.001 | Resource Hijacking: Compute Hijacking | Cryptomining |
| 39 | T1496.004 | Resource Hijacking: Cloud Service Hijacking | Service abuse |
| 40 | T1190 | Exploit Public-Facing Application | App vulnerabilities |

### TIER 5: MEDIUM-LOW (Week 4 - Collection & Impact)
*Data collection and impact techniques*

| # | Technique | Name | Reason |
|---|-----------|------|--------|
| 41 | T1119 | Automated Collection | Scripted data collection |
| 42 | T1074.002 | Data Staged: Remote Data Staging | Staging before exfil |
| 43 | T1114.002 | Email Collection: Remote Email Collection | O365/Workspace email theft |
| 44 | T1114.003 | Email Collection: Email Forwarding Rule | Persistent email access |
| 45 | T1213.003 | Data from Repos: Code Repositories | Source code theft |
| 46 | T1213.006 | Data from Repos: Databases | Database exfiltration |
| 47 | T1485 | Data Destruction | Ransomware/wiper |
| 48 | T1486 | Data Encrypted for Impact | Cloud ransomware |
| 49 | T1531 | Account Access Removal | Lockout attacks |
| 50 | T1489 | Service Stop | Service disruption |

### TIER 6: LOW (Ongoing - Specialised)
*Less common but still relevant*

| # | Technique | Name | Reason |
|---|-----------|------|--------|
| 51 | T1566 | Phishing | Initial access (not cloud-specific) |
| 52 | T1199 | Trusted Relationship | Supply chain/partner abuse |
| 53 | T1195 | Supply Chain Compromise | Software supply chain |
| 54 | T1189 | Drive-by Compromise | Web-based attacks |
| 55 | T1484.002 | Domain Policy Modification: Trust | Federation attacks |
| 56 | T1656 | Impersonation | Social engineering |
| 57 | T1654 | Log Enumeration | Reconnaissance |
| 58 | T1499 | Endpoint Denial of Service | DDoS |
| 59 | T1498 | Network Denial of Service | DDoS |
| 60 | T1657 | Financial Theft | Direct financial attacks |

## Implementation Status

| Status | Count | Techniques |
|--------|-------|------------|
| ✅ Done | 28 | T1078.004, T1098, T1098.001, T1098.003, T1110, T1530, T1562.001, T1562.008, T1552.001, T1552.005, T1528, T1537, T1136.003, T1087.004, T1069.003, T1580, T1578.001, T1526, T1619, T1578.002, T1535, T1621, T1496.001, T1555.006, T1648, T1651, T1485, T1486 |
| 🔄 In Progress | 0 | |
| ⏳ Pending | 32 | All others |

## AWS vs GCP Service Mapping

| Detection Type | AWS Service | GCP Service |
|----------------|-------------|-------------|
| Threat Detection | GuardDuty | Security Command Center |
| Log Analysis | CloudWatch Logs Insights | Cloud Logging |
| Event Routing | EventBridge | Eventarc / Pub/Sub |
| Config Compliance | AWS Config | Security Health Analytics |
| Audit Logs | CloudTrail | Cloud Audit Logs |
| Secrets | Secrets Manager | Secret Manager |
| Identity | IAM, Organizations | Cloud IAM, Resource Manager |
