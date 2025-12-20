# T1036 Masquerading Remediation Template - Summary

## Status: ✅ COMPLETE

The T1036 (Masquerading) remediation template has been successfully created and registered.

## File Location
`/Users/austinosuide/coolstuff/a13e/backend/app/data/remediation_templates/t1036_masquerading.py`

## Template Details

### MITRE ATT&CK Information
- **Technique ID**: T1036
- **Technique Name**: Masquerading
- **Tactic**: TA0005 (Defence Evasion)
- **MITRE URL**: https://attack.mitre.org/techniques/T1036/
- **Severity Score**: 7/10

### Threat Intelligence
- **Known Threat Actors** (10 total):
  - APT28, APT32, APT29, APT41
  - Lazarus Group, FIN13
  - Sandworm Team, ZIRCONIUM
  - TeamTNT, Kimsuky

- **Recent Campaigns** (4 documented):
  1. APT28 WinRAR Masquerading (2024)
  2. APT32 Cobalt Strike Disguise (2023)
  3. Lazarus Group Fake Recruitment (2024)
  4. FIN13 Certutil Abuse (2023)

### Detection Strategies (6 total)

#### AWS Strategies (3)
1. **AWS GuardDuty Execution Anomaly Detection**
   - Type: GuardDuty
   - Effort: Low
   - Cost: $1-5/month
   - Coverage: 75%
   - Includes: CloudFormation + Terraform templates

2. **AWS Lambda Suspicious Function Names**
   - Type: CloudWatch Query
   - Effort: Medium
   - Cost: $5-10/month
   - Coverage: 60%
   - Detects: Lambda functions with masquerading names

3. **AWS ECS Suspicious Container/Task Names**
   - Type: CloudWatch Query
   - Effort: Medium
   - Cost: $5-15/month
   - Coverage: 65%
   - Detects: ECS tasks/containers with suspicious names

#### GCP Strategies (3)
1. **GCP VM Suspicious Process Execution**
   - Type: Cloud Logging Query
   - Effort: Medium
   - Cost: $10-20/month
   - Coverage: 70%
   - Includes: Terraform template

2. **GCP Cloud Functions Masquerading Detection**
   - Type: Cloud Logging Query
   - Effort: Medium
   - Cost: $5-15/month
   - Coverage: 60%
   - Detects: Cloud Functions with suspicious names

3. **GCP GKE Suspicious Container Names**
   - Type: Cloud Logging Query
   - Effort: Medium
   - Cost: $10-20/month
   - Coverage: 65%
   - Detects: Kubernetes pods/containers with masquerading names

### Implementation Details
- **Total Effort Hours**: 8.5 hours
- **Coverage Improvement**: +35% for Defence Evasion tactic
- **False Positive Rate**: Low to Medium (varies by strategy)

### Compliance
- ✅ **UK English**: All content uses British spelling conventions
  - artefacts (not artifacts)
  - unauthorised (not unauthorized)
  - defence (not defense)
- ✅ **Multi-cloud**: Both AWS and GCP strategies included
- ✅ **IaC Templates**: CloudFormation + Terraform (AWS), Terraform (GCP)
- ✅ **3-step format**: All templates use simplified 3-step format
- ✅ **Real threat actors**: All actors verified from MITRE ATT&CK
- ✅ **Investigation steps**: Comprehensive containment and investigation guidance

## Verification

```bash
# Verify template is registered
python3 -c "from app.data.remediation_templates.template_loader import TEMPLATES; \
print(f'T1036 registered: {\"T1036\" in TEMPLATES}'); \
print(f'Total templates: {len(TEMPLATES)}')"

# Output:
# T1036 registered: True
# Total templates: 89
```

## Template Structure

```python
TEMPLATE = RemediationTemplate(
    technique_id="T1036",
    technique_name="Masquerading",
    tactic_ids=["TA0005"],
    threat_context=ThreatContext(...),
    detection_strategies=[...],  # 6 strategies (3 AWS, 3 GCP)
    recommended_order=[...],
    total_effort_hours=8.5,
    coverage_improvement="+35% improvement for Defence Evasion tactic"
)
```

## Next Steps
- Template is ready for use in the application
- Will be available via the API endpoint `/api/remediation/{technique_id}`
- Users can now get remediation guidance for T1036 Masquerading attacks
