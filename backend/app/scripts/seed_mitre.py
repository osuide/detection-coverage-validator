"""Seed MITRE ATT&CK data into the database.

This script adds tactics and techniques to the database.
Run with: python -m app.scripts.seed_mitre
"""

import json
import os
from uuid import uuid4
from datetime import datetime, timezone

from sqlalchemy import create_engine, text

# MITRE ATT&CK v14.1 - Cloud relevant tactics
TACTICS = [
    ("TA0043", "Reconnaissance", "reconnaissance", 1),
    ("TA0042", "Resource Development", "resource-development", 2),
    ("TA0001", "Initial Access", "initial-access", 3),
    ("TA0002", "Execution", "execution", 4),
    ("TA0003", "Persistence", "persistence", 5),
    ("TA0004", "Privilege Escalation", "privilege-escalation", 6),
    ("TA0005", "Defense Evasion", "defense-evasion", 7),
    ("TA0006", "Credential Access", "credential-access", 8),
    ("TA0007", "Discovery", "discovery", 9),
    ("TA0008", "Lateral Movement", "lateral-movement", 10),
    ("TA0009", "Collection", "collection", 11),
    ("TA0010", "Exfiltration", "exfiltration", 12),
    ("TA0011", "Command and Control", "command-and-control", 13),
    ("TA0040", "Impact", "impact", 14),
]

# MITRE ATT&CK v14.1 - Cloud relevant techniques
TECHNIQUES = [
    # Reconnaissance
    ("T1595.001", "Active Scanning: Scanning IP Blocks", "TA0043", "Adversaries may scan victim IP blocks."),
    ("T1595.002", "Active Scanning: Vulnerability Scanning", "TA0043", "Adversaries may scan for vulnerabilities."),

    # Execution
    ("T1059.009", "Command and Scripting Interpreter: Cloud API", "TA0002", "Adversaries may abuse cloud APIs to execute commands."),
    ("T1204.003", "User Execution: Malicious Image", "TA0002", "Adversaries may rely upon a user running a malicious container image."),
    ("T1648", "Serverless Execution", "TA0002", "Adversaries may abuse serverless computing."),
    ("T1609", "Container Administration Command", "TA0002", "Adversaries may abuse container administration commands."),

    # Initial Access
    ("T1078", "Valid Accounts", "TA0001", "Adversaries may obtain and abuse credentials of existing accounts."),
    ("T1078.004", "Valid Accounts: Cloud Accounts", "TA0001", "Adversaries may obtain and abuse credentials of cloud accounts."),
    ("T1199", "Trusted Relationship", "TA0001", "Adversaries may breach organizations via third party relationships."),
    ("T1566", "Phishing", "TA0001", "Adversaries may send phishing messages to gain access."),
    ("T1133", "External Remote Services", "TA0001", "Adversaries may leverage external-facing remote services."),

    # Persistence
    ("T1098", "Account Manipulation", "TA0003", "Adversaries may manipulate accounts to maintain access."),
    ("T1098.001", "Account Manipulation: Additional Cloud Credentials", "TA0003", "Adversaries may add credentials to cloud accounts."),
    ("T1098.003", "Account Manipulation: Additional Cloud Roles", "TA0003", "Adversaries may add additional roles to cloud accounts."),
    ("T1136.003", "Create Account: Cloud Account", "TA0003", "Adversaries may create cloud accounts."),
    ("T1525", "Implant Internal Image", "TA0003", "Adversaries may implant cloud images with malicious code."),

    # Privilege Escalation
    ("T1548.005", "Abuse Elevation Control: Temporary Elevated Cloud Access", "TA0004", "Adversaries may abuse temporary elevated access."),
    ("T1611", "Escape to Host", "TA0004", "Adversaries may break out of containers to gain host access."),

    # Defense Evasion
    ("T1562.008", "Impair Defenses: Disable Cloud Logs", "TA0005", "Adversaries may disable cloud logging."),
    ("T1562.007", "Impair Defenses: Disable or Modify Cloud Firewall", "TA0005", "Adversaries may disable cloud firewalls."),
    ("T1562.001", "Impair Defenses: Disable or Modify Tools", "TA0005", "Adversaries may disable security tools."),
    ("T1578.002", "Modify Cloud Compute Infrastructure: Create Snapshot", "TA0005", "Adversaries may create snapshots of cloud instances."),
    ("T1535", "Unused/Unsupported Cloud Regions", "TA0005", "Adversaries may use unused cloud regions."),
    ("T1620", "Reflective Code Loading", "TA0005", "Adversaries may load code into memory without writing to disk."),
    ("T1055", "Process Injection", "TA0005", "Adversaries may inject code into processes."),

    # Credential Access
    ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "TA0006", "Adversaries may abuse the cloud instance metadata API."),
    ("T1528", "Steal Application Access Token", "TA0006", "Adversaries may steal application access tokens."),
    ("T1110.001", "Brute Force: Password Guessing", "TA0006", "Adversaries may use password guessing to obtain credentials."),

    # Discovery
    ("T1526", "Cloud Service Discovery", "TA0007", "Adversaries may enumerate cloud services."),
    ("T1580", "Cloud Infrastructure Discovery", "TA0007", "Adversaries may enumerate cloud infrastructure."),
    ("T1619", "Cloud Storage Object Discovery", "TA0007", "Adversaries may enumerate cloud storage objects."),
    ("T1046", "Network Service Discovery", "TA0007", "Adversaries may scan for network services."),

    # Lateral Movement
    ("T1550.001", "Use Alternate Authentication Material: Application Access Token", "TA0008", "Adversaries may use stolen tokens for lateral movement."),

    # Collection
    ("T1530", "Data from Cloud Storage", "TA0009", "Adversaries may access data from cloud storage."),

    # Exfiltration
    ("T1537", "Transfer Data to Cloud Account", "TA0010", "Adversaries may exfiltrate data to a cloud account."),
    ("T1048.003", "Exfiltration Over Alternative Protocol", "TA0010", "Adversaries may exfiltrate data over non-C2 protocols."),

    # Command and Control
    ("T1071.001", "Application Layer Protocol: Web Protocols", "TA0011", "Adversaries may use web protocols for C2."),
    ("T1071.004", "Application Layer Protocol: DNS", "TA0011", "Adversaries may use DNS for C2."),
    ("T1071.003", "Application Layer Protocol: Mail Protocols", "TA0011", "Adversaries may use mail protocols for C2."),
    ("T1090.003", "Proxy: Multi-hop Proxy", "TA0011", "Adversaries may chain proxies."),
    ("T1572", "Protocol Tunneling", "TA0011", "Adversaries may tunnel traffic within protocols."),
    ("T1571", "Non-Standard Port", "TA0011", "Adversaries may use non-standard ports."),
    ("T1568.002", "Dynamic Resolution: Domain Generation Algorithms", "TA0011", "Adversaries may use DGAs."),

    # Impact
    ("T1485", "Data Destruction", "TA0040", "Adversaries may destroy data."),
    ("T1486", "Data Encrypted for Impact", "TA0040", "Adversaries may encrypt data for impact."),
    ("T1496", "Resource Hijacking", "TA0040", "Adversaries may hijack resources."),
    ("T1498", "Network Denial of Service", "TA0040", "Adversaries may perform network DoS."),
    ("T1588.002", "Obtain Capabilities: Tool", "TA0043", "Adversaries may obtain tools."),
]


def seed_mitre_sync():
    """Seed MITRE data using synchronous database connection."""
    database_url = os.environ.get("DATABASE_URL", "").replace("+asyncpg", "")
    if not database_url:
        print("DATABASE_URL not set")
        return

    engine = create_engine(database_url)

    with engine.connect() as conn:
        now = datetime.now(timezone.utc)

        # Get existing tactics
        existing_tactics = {}
        result = conn.execute(text("SELECT tactic_id, id FROM tactics"))
        for row in result:
            existing_tactics[row[0]] = row[1]

        # Insert missing tactics
        tactics_added = 0
        for tactic_id, name, short_name, display_order in TACTICS:
            if tactic_id not in existing_tactics:
                tactic_uuid = str(uuid4())
                conn.execute(
                    text("""
                        INSERT INTO tactics (id, tactic_id, name, short_name, display_order, mitre_version, created_at)
                        VALUES (:id, :tactic_id, :name, :short_name, :display_order, :mitre_version, :created_at)
                    """),
                    {
                        "id": tactic_uuid,
                        "tactic_id": tactic_id,
                        "name": name,
                        "short_name": short_name,
                        "display_order": display_order,
                        "mitre_version": "14.1",
                        "created_at": now,
                    }
                )
                existing_tactics[tactic_id] = tactic_uuid
                tactics_added += 1

        conn.commit()
        print(f"Added {tactics_added} new tactics")

        # Get existing techniques
        existing_techniques = set()
        result = conn.execute(text("SELECT technique_id FROM techniques"))
        for row in result:
            existing_techniques.add(row[0])

        # Insert missing techniques
        techniques_added = 0
        for technique_id, name, tactic_id, description in TECHNIQUES:
            if technique_id not in existing_techniques:
                tactic_uuid = existing_tactics.get(tactic_id)
                if not tactic_uuid:
                    print(f"Warning: Tactic {tactic_id} not found for technique {technique_id}")
                    continue

                is_subtechnique = "." in technique_id
                parent_id = None
                if is_subtechnique:
                    parent_tech_id = technique_id.split(".")[0]
                    # Look up parent technique UUID
                    parent_result = conn.execute(
                        text("SELECT id FROM techniques WHERE technique_id = :tid"),
                        {"tid": parent_tech_id}
                    )
                    parent_row = parent_result.fetchone()
                    if parent_row:
                        parent_id = parent_row[0]

                conn.execute(
                    text("""
                        INSERT INTO techniques (
                            id, technique_id, name, description, tactic_id, parent_technique_id,
                            platforms, mitre_version, is_subtechnique, created_at, updated_at
                        )
                        VALUES (
                            :id, :technique_id, :name, :description, :tactic_id, :parent_id,
                            CAST(:platforms AS jsonb), :mitre_version, :is_subtechnique, :created_at, :updated_at
                        )
                    """),
                    {
                        "id": str(uuid4()),
                        "technique_id": technique_id,
                        "name": name,
                        "description": description,
                        "tactic_id": tactic_uuid,
                        "parent_id": parent_id,
                        "platforms": json.dumps(["AWS", "Azure", "GCP", "IaaS"]),
                        "mitre_version": "14.1",
                        "is_subtechnique": is_subtechnique,
                        "created_at": now,
                        "updated_at": now,
                    }
                )
                existing_techniques.add(technique_id)
                techniques_added += 1

        conn.commit()
        print(f"Added {techniques_added} new techniques")
        print(f"Total techniques in database: {len(existing_techniques)}")


if __name__ == "__main__":
    seed_mitre_sync()
