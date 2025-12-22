#!/usr/bin/env python3
"""Build comprehensive compliance mappings from MITRE CTID sources.

Downloads NIST 800-53 Rev 5 controls and mappings from MITRE CTID,
adds cloud applicability metadata, and generates JSON files for loading.

Sources:
- NIST 800-53: https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings
"""

import json
import urllib.request
from typing import Optional
from pathlib import Path

# MITRE CTID URLs for NIST 800-53 Rev 5 (ATT&CK v12.1)
NIST_CONTROLS_URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r5/stix/nist800-53-r5-controls.json"
NIST_MAPPINGS_URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r5/stix/nist800-53-r5-mappings.json"

# Output directory
OUTPUT_DIR = Path(__file__).parent.parent / "app" / "data" / "compliance_mappings"

# Cloud applicability by control family
# Based on AWS/GCP shared responsibility models
CLOUD_APPLICABILITY = {
    # Highly relevant - directly detectable in cloud environments
    "AC": "highly_relevant",  # Access Control
    "AU": "highly_relevant",  # Audit and Accountability
    "CM": "highly_relevant",  # Configuration Management
    "IA": "highly_relevant",  # Identification and Authentication
    "SC": "highly_relevant",  # System and Communications Protection
    "SI": "highly_relevant",  # System and Information Integrity
    "CA": "highly_relevant",  # Security Assessment and Authorisation
    "RA": "highly_relevant",  # Risk Assessment
    "IR": "highly_relevant",  # Incident Response
    "CP": "moderately_relevant",  # Contingency Planning
    "SA": "moderately_relevant",  # System and Services Acquisition
    "SR": "moderately_relevant",  # Supply Chain Risk Management
    # Informational - not directly cloud-detectable
    "AT": "informational",  # Awareness and Training
    "PL": "informational",  # Planning
    "PM": "informational",  # Program Management
    "PS": "informational",  # Personnel Security
    "PT": "informational",  # PII Processing and Transparency
    # Provider responsibility - cloud provider manages these
    "PE": "provider_responsibility",  # Physical and Environmental Protection
    "MA": "provider_responsibility",  # Maintenance
    "MP": "provider_responsibility",  # Media Protection
}

# Cloud context by control family
CLOUD_CONTEXT = {
    "AC": {
        "aws_services": ["IAM", "Organizations", "STS", "Cognito", "SSO"],
        "gcp_services": ["Cloud IAM", "Identity Platform", "Resource Manager"],
        "shared_responsibility": "customer",
    },
    "AU": {
        "aws_services": ["CloudTrail", "CloudWatch Logs", "S3", "Athena"],
        "gcp_services": ["Cloud Audit Logs", "Cloud Logging", "BigQuery"],
        "shared_responsibility": "customer",
    },
    "CM": {
        "aws_services": ["Config", "Systems Manager", "CloudFormation"],
        "gcp_services": ["Asset Inventory", "Cloud Build", "Deployment Manager"],
        "shared_responsibility": "customer",
    },
    "IA": {
        "aws_services": ["IAM", "Cognito", "SSO", "STS", "Secrets Manager"],
        "gcp_services": ["Cloud IAM", "Identity Platform", "Secret Manager"],
        "shared_responsibility": "customer",
    },
    "SC": {
        "aws_services": ["VPC", "Security Groups", "NACLs", "KMS", "ACM", "WAF"],
        "gcp_services": ["VPC", "Firewall Rules", "Cloud KMS", "Cloud Armor"],
        "shared_responsibility": "customer",
    },
    "SI": {
        "aws_services": ["GuardDuty", "Inspector", "Macie", "Security Hub"],
        "gcp_services": ["Security Command Center", "Cloud IDS", "Chronicle"],
        "shared_responsibility": "customer",
    },
    "CA": {
        "aws_services": ["Security Hub", "Inspector", "Trusted Advisor"],
        "gcp_services": ["Security Command Center", "Cloud Asset Inventory"],
        "shared_responsibility": "customer",
    },
    "RA": {
        "aws_services": ["Inspector", "GuardDuty", "Security Hub"],
        "gcp_services": ["Security Command Center", "Cloud Asset Inventory"],
        "shared_responsibility": "customer",
    },
    "IR": {
        "aws_services": ["EventBridge", "Lambda", "SNS", "Security Hub"],
        "gcp_services": ["Cloud Functions", "Pub/Sub", "Security Command Center"],
        "shared_responsibility": "customer",
    },
    "CP": {
        "aws_services": ["Backup", "S3", "RDS Snapshots", "EBS Snapshots"],
        "gcp_services": ["Cloud Storage", "Persistent Disk Snapshots"],
        "shared_responsibility": "customer",
    },
    "SA": {
        "aws_services": ["Marketplace", "ECR", "CodeArtifact"],
        "gcp_services": ["Artifact Registry", "Cloud Build"],
        "shared_responsibility": "shared",
    },
    "SR": {
        "aws_services": ["Config", "Organizations"],
        "gcp_services": ["Cloud Asset Inventory"],
        "shared_responsibility": "shared",
    },
    "AT": {
        "aws_services": [],
        "gcp_services": [],
        "shared_responsibility": "customer",
    },
    "PL": {
        "aws_services": [],
        "gcp_services": [],
        "shared_responsibility": "customer",
    },
    "PM": {
        "aws_services": [],
        "gcp_services": [],
        "shared_responsibility": "customer",
    },
    "PS": {
        "aws_services": [],
        "gcp_services": [],
        "shared_responsibility": "customer",
    },
    "PT": {
        "aws_services": ["Macie"],
        "gcp_services": ["DLP API"],
        "shared_responsibility": "customer",
    },
    "PE": {
        "aws_services": [],
        "gcp_services": [],
        "shared_responsibility": "provider",
    },
    "MA": {
        "aws_services": [],
        "gcp_services": [],
        "shared_responsibility": "provider",
    },
    "MP": {
        "aws_services": [],
        "gcp_services": [],
        "shared_responsibility": "provider",
    },
}

# Control family names
FAMILY_NAMES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Security Assessment and Authorisation",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "PII Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}


def fetch_json(url: str) -> dict:
    """Fetch JSON from URL or local file."""
    # Check for local cached files
    script_dir = Path(__file__).parent
    if "nist800-53-r5-controls.json" in url:
        local_path = script_dir / "data" / "nist-controls.json"
    elif "nist800-53-r5-mappings.json" in url:
        local_path = script_dir / "data" / "nist-mappings.json"
    else:
        local_path = None

    if local_path and local_path.exists():
        print(f"Loading from: {local_path}")
        with open(local_path, "r", encoding="utf-8") as f:
            return json.load(f)

    print(f"Fetching: {url}")
    with urllib.request.urlopen(url) as response:
        return json.loads(response.read().decode("utf-8"))


def get_control_id(control: dict) -> Optional[str]:
    """Extract control ID from STIX object."""
    for ref in control.get("external_references", []):
        if ref.get("source_name") == "NIST 800-53 Revision 5":
            return ref.get("external_id")
    return None


def get_family(control_id: str) -> str:
    """Extract family from control ID (e.g., 'AC-2' -> 'AC')."""
    if "-" in control_id:
        return control_id.split("-")[0]
    return control_id[:2]


def is_enhancement(control_id: str) -> bool:
    """Check if control is an enhancement (e.g., 'AC-2(1)')."""
    return "(" in control_id


def get_priority(family: str, control_id: str) -> Optional[str]:
    """Assign priority based on family and control importance."""
    # P1: Critical security controls
    p1_controls = {
        "AC-2",
        "AC-3",
        "AC-6",
        "AC-17",
        "AU-2",
        "AU-3",
        "AU-6",
        "AU-12",
        "CM-2",
        "CM-6",
        "CM-7",
        "CM-8",
        "IA-2",
        "IA-5",
        "IA-8",
        "SC-7",
        "SC-8",
        "SC-12",
        "SC-13",
        "SC-28",
        "SI-2",
        "SI-3",
        "SI-4",
        "SI-7",
    }
    # P2: Important controls
    p2_controls = {
        "AC-4",
        "AC-5",
        "AC-7",
        "AC-11",
        "AC-12",
        "AU-4",
        "AU-5",
        "AU-8",
        "AU-9",
        "CM-3",
        "CM-4",
        "CM-5",
        "IA-3",
        "IA-4",
        "IA-6",
        "IR-4",
        "IR-5",
        "IR-6",
        "SC-2",
        "SC-3",
        "SC-4",
        "SC-5",
        "SI-5",
        "SI-6",
        "SI-10",
    }

    base_control = control_id.split("(")[0]
    if base_control in p1_controls:
        return "P1"
    elif base_control in p2_controls:
        return "P2"
    elif family in ("AC", "AU", "CM", "IA", "SC", "SI"):
        return "P3"
    return None


def load_attack_techniques() -> dict:
    """Load ATT&CK technique STIX ID to technique ID mapping."""
    script_dir = Path(__file__).parent
    attack_path = script_dir / "data" / "enterprise-attack.json"

    if not attack_path.exists():
        print("WARNING: ATT&CK data not found, technique IDs will not be resolved")
        return {}

    print(f"Loading ATT&CK data from: {attack_path}")
    with open(attack_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    technique_map = {}
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            stix_id = obj["id"]
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_map[stix_id] = ref.get("external_id")
                    break

    print(f"Loaded {len(technique_map)} ATT&CK techniques")
    return technique_map


def build_nist_mappings() -> dict:
    """Build NIST 800-53 Rev 5 mappings."""
    print("\n=== Building NIST 800-53 Rev 5 Mappings ===\n")

    # Load ATT&CK technique mapping
    technique_map = load_attack_techniques()

    # Fetch data
    controls_data = fetch_json(NIST_CONTROLS_URL)
    mappings_data = fetch_json(NIST_MAPPINGS_URL)

    # Extract controls
    controls = {}
    for obj in controls_data["objects"]:
        if obj.get("type") == "course-of-action":
            control_id = get_control_id(obj)
            if control_id:
                controls[obj["id"]] = {
                    "stix_id": obj["id"],
                    "control_id": control_id,
                    "name": obj.get("name", "").replace(f"{control_id}: ", ""),
                    "description": obj.get("description", ""),
                }

    print(f"Found {len(controls)} controls")

    # Extract mappings
    control_techniques = {}
    for obj in mappings_data["objects"]:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "mitigates"
        ):
            source_id = obj["source_ref"]
            target_id = obj["target_ref"]
            if source_id in controls:
                if source_id not in control_techniques:
                    control_techniques[source_id] = []
                # Extract technique ID from target_ref
                # Format: attack-pattern--<uuid>
                control_techniques[source_id].append(target_id)

    print(
        f"Found {sum(len(t) for t in control_techniques.values())} technique mappings"
    )
    print(f"Controls with mappings: {len(control_techniques)}")

    # Build output structure
    framework = {
        "framework_id": "nist-800-53-r5",
        "name": "NIST 800-53 Rev 5",
        "version": "5.0",
        "description": "NIST Special Publication 800-53 Revision 5: Security and Privacy Controls for Information Systems and Organisations. Mappings from MITRE CTID.",
        "source_url": "https://center-for-threat-informed-defense.github.io/mappings-explorer/external/nist/",
    }

    output_controls = []
    display_order = 0

    # Only include controls that have technique mappings
    for stix_id, techniques in sorted(
        control_techniques.items(), key=lambda x: controls[x[0]]["control_id"]
    ):
        control = controls[stix_id]
        control_id = control["control_id"]
        family = get_family(control_id)

        # Get technique mappings - resolve STIX IDs to technique IDs
        technique_mappings = []
        seen_techniques = set()
        for technique_stix_id in techniques:
            technique_id = technique_map.get(technique_stix_id)
            if technique_id and technique_id not in seen_techniques:
                technique_mappings.append(
                    {
                        "technique_id": technique_id,
                        "mapping_type": "mitigates",
                    }
                )
                seen_techniques.add(technique_id)

        output_control = {
            "control_id": control_id,
            "control_family": FAMILY_NAMES.get(family, family),
            "name": control["name"],
            "description": (
                control["description"][:500] if control["description"] else None
            ),
            "priority": get_priority(family, control_id),
            "is_enhancement": is_enhancement(control_id),
            "cloud_applicability": CLOUD_APPLICABILITY.get(family, "informational"),
            "cloud_context": CLOUD_CONTEXT.get(family),
            "technique_mappings": technique_mappings,
        }

        output_controls.append(output_control)
        display_order += 1

    print(f"\nOutput controls: {len(output_controls)}")

    # Count by family
    family_counts = {}
    for c in output_controls:
        f = get_family(c["control_id"])
        family_counts[f] = family_counts.get(f, 0) + 1

    print("\nControls by family:")
    for f in sorted(family_counts.keys()):
        app = CLOUD_APPLICABILITY.get(f, "unknown")
        print(f"  {f} ({FAMILY_NAMES.get(f, f)}): {family_counts[f]} - {app}")

    return {"framework": framework, "controls": output_controls}


def main():
    """Main entry point."""
    # Build NIST mappings
    nist_data = build_nist_mappings()

    # Write output
    output_file = OUTPUT_DIR / "nist_800_53_r5_full.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(nist_data, f, indent=2, ensure_ascii=False)

    print(f"\nWritten to: {output_file}")
    print(f"Total controls: {len(nist_data['controls'])}")


if __name__ == "__main__":
    main()
