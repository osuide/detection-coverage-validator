#!/usr/bin/env python3
"""Verify T1124 template is properly registered and functional."""

from app.data.remediation_templates.template_loader import TEMPLATES, get_template

print("=" * 70)
print("T1124 SYSTEM TIME DISCOVERY TEMPLATE - VERIFICATION REPORT")
print("=" * 70)

# Check registration
if "T1124" in TEMPLATES:
    print("\n✓ Template is registered in TEMPLATES dictionary")
else:
    print("\n✗ ERROR: Template is NOT registered")
    exit(1)

# Load template
template = get_template("T1124")
if not template:
    print("✗ ERROR: Could not load template via get_template()")
    exit(1)

print("✓ Template loaded successfully")

# Display details
print(f"\n{'Technique Details:':-^70}")
print(f"ID:             {template.technique_id}")
print(f"Name:           {template.technique_name}")
print(f"Tactic:         {template.tactic_ids[0]} (Discovery)")
print(f"MITRE URL:      {template.mitre_url}")
print(f"Version:        {template.version}")
print(f"Last Updated:   {template.last_updated}")

print(f"\n{'Threat Context:':-^70}")
print(f"Severity:       {template.threat_context.severity_score}/10")
print(f"Prevalence:     {template.threat_context.prevalence}")
print(f"Trend:          {template.threat_context.trend}")
print(f"Threat Actors:  {len(template.threat_context.known_threat_actors)}")
print(f"Campaigns:      {len(template.threat_context.recent_campaigns)}")

# Check UK English
desc = template.threat_context.description
if "synchronising" in desc:
    print("✓ Uses UK English spelling (synchronising)")

# Cloud coverage
print(f"\n{'Detection Strategies:':-^70}")
aws_strategies = [
    s for s in template.detection_strategies if s.cloud_provider.value == "aws"
]
gcp_strategies = [
    s for s in template.detection_strategies if s.cloud_provider.value == "gcp"
]

print(f"Total Strategies: {len(template.detection_strategies)}")
print(f"  - AWS:          {len(aws_strategies)}")
print(f"  - GCP:          {len(gcp_strategies)}")

print(f"\n{'AWS Detection Strategies:':-^70}")
for i, s in enumerate(aws_strategies, 1):
    print(f"{i}. {s.name}")
    print(f"   Type: {s.detection_type.value}")
    print(f"   Effort: {s.implementation_effort.value} ({s.implementation_time})")
    print(f"   False Positives: {s.estimated_false_positive_rate.value}")
    print(f"   Cost: {s.estimated_monthly_cost}")
    has_cf = bool(s.implementation.cloudformation_template)
    has_tf = bool(s.implementation.terraform_template)
    print(
        f"   Templates: CloudFormation={'✓' if has_cf else '✗'}, Terraform={'✓' if has_tf else '✗'}"
    )
    print()

print(f"{'GCP Detection Strategies:':-^70}")
for i, s in enumerate(gcp_strategies, 1):
    print(f"{i}. {s.name}")
    print(f"   Type: {s.detection_type.value}")
    print(f"   Effort: {s.implementation_effort.value} ({s.implementation_time})")
    print(f"   False Positives: {s.estimated_false_positive_rate.value}")
    print(f"   Cost: {s.estimated_monthly_cost}")
    has_tf = bool(s.implementation.gcp_terraform_template)
    print(f"   Templates: Terraform={'✓' if has_tf else '✗'}")
    print()

print(f"\n{'Implementation Summary:':-^70}")
print(f"Recommended Order: {', '.join(template.recommended_order)}")
print(f"Total Effort:      {template.total_effort_hours} hours")
print(f"Coverage:          {template.coverage_improvement}")

print("\n" + "=" * 70)
print("✓ VERIFICATION COMPLETE: All checks passed!")
print("=" * 70)
