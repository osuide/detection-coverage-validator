"""Seed MITRE ATT&CK data into the database.

This script adds tactics and techniques to the database.
Based on MITRE ATT&CK v14.1 IaaS Cloud Matrix.
Run with: python -m app.scripts.seed_mitre

Source: https://attack.mitre.org/matrices/enterprise/cloud/iaas/
"""

import json
import os
from uuid import uuid4
from datetime import datetime, timezone

from sqlalchemy import create_engine, text

# MITRE ATT&CK v14.1 - All Enterprise Tactics
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

# MITRE ATT&CK v14.1 - Complete IaaS Cloud Matrix Techniques
# Format: (technique_id, name, tactic_id, description)
TECHNIQUES = [
    # ==================== RECONNAISSANCE (TA0043) ====================
    ("T1595", "Active Scanning", "TA0043", "Adversaries may execute active reconnaissance scans to gather information."),
    ("T1595.001", "Active Scanning: Scanning IP Blocks", "TA0043", "Adversaries may scan victim IP blocks to gather information."),
    ("T1595.002", "Active Scanning: Vulnerability Scanning", "TA0043", "Adversaries may scan for vulnerabilities in victim systems."),
    ("T1595.003", "Active Scanning: Wordlist Scanning", "TA0043", "Adversaries may scan for valid cloud resources using wordlists."),
    ("T1592", "Gather Victim Host Information", "TA0043", "Adversaries may gather information about victim hosts."),
    ("T1589", "Gather Victim Identity Information", "TA0043", "Adversaries may gather information about victim identities."),
    ("T1590", "Gather Victim Network Information", "TA0043", "Adversaries may gather information about victim networks."),
    ("T1591", "Gather Victim Org Information", "TA0043", "Adversaries may gather information about victim organizations."),
    ("T1598", "Phishing for Information", "TA0043", "Adversaries may send phishing messages to elicit sensitive information."),
    ("T1597", "Search Closed Sources", "TA0043", "Adversaries may search private data sources for victim information."),
    ("T1596", "Search Open Technical Databases", "TA0043", "Adversaries may search technical databases for victim information."),
    ("T1593", "Search Open Websites/Domains", "TA0043", "Adversaries may search websites for victim information."),
    ("T1594", "Search Victim-Owned Websites", "TA0043", "Adversaries may search victim-owned websites for information."),

    # ==================== RESOURCE DEVELOPMENT (TA0042) ====================
    ("T1583", "Acquire Infrastructure", "TA0042", "Adversaries may buy, lease, or rent infrastructure."),
    ("T1583.006", "Acquire Infrastructure: Web Services", "TA0042", "Adversaries may use web services for operations."),
    ("T1586", "Compromise Accounts", "TA0042", "Adversaries may compromise accounts for use in operations."),
    ("T1586.003", "Compromise Accounts: Cloud Accounts", "TA0042", "Adversaries may compromise cloud accounts."),
    ("T1584", "Compromise Infrastructure", "TA0042", "Adversaries may compromise infrastructure."),
    ("T1587", "Develop Capabilities", "TA0042", "Adversaries may develop their own capabilities."),
    ("T1585", "Establish Accounts", "TA0042", "Adversaries may establish accounts for operations."),
    ("T1588", "Obtain Capabilities", "TA0042", "Adversaries may obtain capabilities rather than develop them."),
    ("T1588.002", "Obtain Capabilities: Tool", "TA0042", "Adversaries may obtain tools for operations."),
    ("T1608", "Stage Capabilities", "TA0042", "Adversaries may stage capabilities on infrastructure."),

    # ==================== INITIAL ACCESS (TA0001) ====================
    ("T1190", "Exploit Public-Facing Application", "TA0001", "Adversaries may exploit vulnerabilities in public-facing applications."),
    ("T1199", "Trusted Relationship", "TA0001", "Adversaries may breach via trusted third-party relationships."),
    ("T1078", "Valid Accounts", "TA0001", "Adversaries may obtain and abuse credentials of existing accounts."),
    ("T1078.001", "Valid Accounts: Default Accounts", "TA0001", "Adversaries may obtain and abuse default accounts."),
    ("T1078.004", "Valid Accounts: Cloud Accounts", "TA0001", "Adversaries may obtain and abuse cloud account credentials."),
    ("T1566", "Phishing", "TA0001", "Adversaries may send phishing messages to gain access."),
    ("T1566.001", "Phishing: Spearphishing Attachment", "TA0001", "Adversaries may send spearphishing with attachments."),
    ("T1566.002", "Phishing: Spearphishing Link", "TA0001", "Adversaries may send spearphishing with links."),
    ("T1133", "External Remote Services", "TA0001", "Adversaries may leverage external-facing remote services."),
    ("T1200", "Hardware Additions", "TA0001", "Adversaries may introduce malicious hardware."),

    # ==================== EXECUTION (TA0002) ====================
    ("T1651", "Cloud Administration Command", "TA0002", "Adversaries may abuse cloud management services."),
    ("T1059", "Command and Scripting Interpreter", "TA0002", "Adversaries may abuse command and script interpreters."),
    ("T1059.009", "Command and Scripting Interpreter: Cloud API", "TA0002", "Adversaries may abuse cloud APIs."),
    ("T1648", "Serverless Execution", "TA0002", "Adversaries may abuse serverless computing."),
    ("T1204", "User Execution", "TA0002", "Adversaries may rely upon user execution."),
    ("T1204.001", "User Execution: Malicious Link", "TA0002", "Adversaries may rely upon users clicking malicious links."),
    ("T1204.002", "User Execution: Malicious File", "TA0002", "Adversaries may rely upon users executing malicious files."),
    ("T1204.003", "User Execution: Malicious Image", "TA0002", "Adversaries may rely upon users running malicious images."),
    ("T1609", "Container Administration Command", "TA0002", "Adversaries may abuse container administration commands."),
    ("T1610", "Deploy Container", "TA0002", "Adversaries may deploy containers for execution."),

    # ==================== PERSISTENCE (TA0003) ====================
    ("T1098", "Account Manipulation", "TA0003", "Adversaries may manipulate accounts to maintain access."),
    ("T1098.001", "Account Manipulation: Additional Cloud Credentials", "TA0003", "Adversaries may add credentials to cloud accounts."),
    ("T1098.003", "Account Manipulation: Additional Cloud Roles", "TA0003", "Adversaries may add roles to cloud accounts."),
    ("T1098.004", "Account Manipulation: SSH Authorized Keys", "TA0003", "Adversaries may modify SSH authorized keys."),
    ("T1098.006", "Account Manipulation: Additional Container Cluster Roles", "TA0003", "Adversaries may add Kubernetes roles."),
    ("T1136", "Create Account", "TA0003", "Adversaries may create accounts for persistence."),
    ("T1136.003", "Create Account: Cloud Account", "TA0003", "Adversaries may create cloud accounts."),
    ("T1546", "Event Triggered Execution", "TA0003", "Adversaries may establish persistence via event triggers."),
    ("T1546.008", "Event Triggered Execution: Serverless", "TA0003", "Adversaries may use serverless functions for persistence."),
    ("T1525", "Implant Internal Image", "TA0003", "Adversaries may implant malicious images."),
    ("T1556", "Modify Authentication Process", "TA0003", "Adversaries may modify authentication mechanisms."),
    ("T1556.006", "Modify Authentication Process: Multi-Factor Authentication", "TA0003", "Adversaries may modify MFA."),
    ("T1556.007", "Modify Authentication Process: Hybrid Identity", "TA0003", "Adversaries may modify hybrid identity."),
    ("T1556.009", "Modify Authentication Process: Conditional Access Policies", "TA0003", "Adversaries may modify conditional access."),

    # ==================== PRIVILEGE ESCALATION (TA0004) ====================
    ("T1548", "Abuse Elevation Control Mechanism", "TA0004", "Adversaries may abuse elevation control mechanisms."),
    ("T1548.005", "Abuse Elevation Control: Temporary Elevated Cloud Access", "TA0004", "Adversaries may abuse temporary cloud access."),
    ("T1611", "Escape to Host", "TA0004", "Adversaries may break out of containers."),
    ("T1068", "Exploitation for Privilege Escalation", "TA0004", "Adversaries may exploit vulnerabilities for escalation."),

    # ==================== DEFENSE EVASION (TA0005) ====================
    ("T1211", "Exploitation for Defense Evasion", "TA0005", "Adversaries may exploit vulnerabilities to evade defenses."),
    ("T1562", "Impair Defenses", "TA0005", "Adversaries may impair defensive capabilities."),
    ("T1562.001", "Impair Defenses: Disable or Modify Tools", "TA0005", "Adversaries may disable security tools."),
    ("T1562.007", "Impair Defenses: Disable or Modify Cloud Firewall", "TA0005", "Adversaries may disable cloud firewalls."),
    ("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs", "TA0005", "Adversaries may disable cloud logging."),
    ("T1578", "Modify Cloud Compute Infrastructure", "TA0005", "Adversaries may modify cloud compute."),
    ("T1578.001", "Modify Cloud Compute: Create Snapshot", "TA0005", "Adversaries may create snapshots."),
    ("T1578.002", "Modify Cloud Compute: Create Cloud Instance", "TA0005", "Adversaries may create cloud instances."),
    ("T1578.003", "Modify Cloud Compute: Delete Cloud Instance", "TA0005", "Adversaries may delete cloud instances."),
    ("T1578.004", "Modify Cloud Compute: Revert Cloud Instance", "TA0005", "Adversaries may revert cloud instances."),
    ("T1578.005", "Modify Cloud Compute: Modify Cloud Compute Configurations", "TA0005", "Adversaries may modify cloud configurations."),
    ("T1666", "Modify Cloud Resource Hierarchy", "TA0005", "Adversaries may modify cloud resource hierarchy."),
    ("T1535", "Unused/Unsupported Cloud Regions", "TA0005", "Adversaries may use unused cloud regions."),
    ("T1550", "Use Alternate Authentication Material", "TA0005", "Adversaries may use alternate authentication."),
    ("T1550.001", "Use Alternate Authentication: Application Access Token", "TA0005", "Adversaries may use application tokens."),
    ("T1550.004", "Use Alternate Authentication: Web Session Cookie", "TA0005", "Adversaries may use web session cookies."),
    ("T1620", "Reflective Code Loading", "TA0005", "Adversaries may load code reflectively."),
    ("T1055", "Process Injection", "TA0005", "Adversaries may inject code into processes."),
    ("T1027", "Obfuscated Files or Information", "TA0005", "Adversaries may obfuscate files."),
    ("T1027.006", "Obfuscated Files: HTML Smuggling", "TA0005", "Adversaries may use HTML smuggling."),
    ("T1612", "Build Image on Host", "TA0005", "Adversaries may build container images on hosts."),

    # ==================== CREDENTIAL ACCESS (TA0006) ====================
    ("T1110", "Brute Force", "TA0006", "Adversaries may use brute force to obtain credentials."),
    ("T1110.001", "Brute Force: Password Guessing", "TA0006", "Adversaries may guess passwords."),
    ("T1110.003", "Brute Force: Password Spraying", "TA0006", "Adversaries may spray passwords."),
    ("T1110.004", "Brute Force: Credential Stuffing", "TA0006", "Adversaries may stuff credentials."),
    ("T1555", "Credentials from Password Stores", "TA0006", "Adversaries may steal credentials from stores."),
    ("T1555.006", "Credentials from Password Stores: Cloud Secrets Management Stores", "TA0006", "Adversaries may steal from cloud secret stores."),
    ("T1606", "Forge Web Credentials", "TA0006", "Adversaries may forge web credentials."),
    ("T1606.001", "Forge Web Credentials: Web Cookies", "TA0006", "Adversaries may forge web cookies."),
    ("T1606.002", "Forge Web Credentials: SAML Tokens", "TA0006", "Adversaries may forge SAML tokens."),
    ("T1621", "Multi-Factor Authentication Request Generation", "TA0006", "Adversaries may generate MFA requests."),
    ("T1040", "Network Sniffing", "TA0006", "Adversaries may sniff network traffic."),
    ("T1528", "Steal Application Access Token", "TA0006", "Adversaries may steal application tokens."),
    ("T1552", "Unsecured Credentials", "TA0006", "Adversaries may search for unsecured credentials."),
    ("T1552.001", "Unsecured Credentials: Credentials In Files", "TA0006", "Adversaries may search files for credentials."),
    ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "TA0006", "Adversaries may abuse cloud metadata API."),
    ("T1552.007", "Unsecured Credentials: Container API", "TA0006", "Adversaries may abuse container APIs."),

    # ==================== DISCOVERY (TA0007) ====================
    ("T1087", "Account Discovery", "TA0007", "Adversaries may enumerate accounts."),
    ("T1087.004", "Account Discovery: Cloud Account", "TA0007", "Adversaries may enumerate cloud accounts."),
    ("T1580", "Cloud Infrastructure Discovery", "TA0007", "Adversaries may discover cloud infrastructure."),
    ("T1538", "Cloud Service Dashboard", "TA0007", "Adversaries may use cloud dashboards for discovery."),
    ("T1526", "Cloud Service Discovery", "TA0007", "Adversaries may discover cloud services."),
    ("T1619", "Cloud Storage Object Discovery", "TA0007", "Adversaries may discover cloud storage objects."),
    ("T1613", "Container and Resource Discovery", "TA0007", "Adversaries may discover containers."),
    ("T1680", "Local Storage Discovery", "TA0007", "Adversaries may discover local storage."),
    ("T1654", "Log Enumeration", "TA0007", "Adversaries may enumerate logs."),
    ("T1046", "Network Service Discovery", "TA0007", "Adversaries may discover network services."),
    ("T1135", "Network Share Discovery", "TA0007", "Adversaries may discover network shares."),
    ("T1201", "Password Policy Discovery", "TA0007", "Adversaries may discover password policies."),
    ("T1069", "Permission Groups Discovery", "TA0007", "Adversaries may discover permission groups."),
    ("T1069.003", "Permission Groups Discovery: Cloud Groups", "TA0007", "Adversaries may discover cloud groups."),
    ("T1518", "Software Discovery", "TA0007", "Adversaries may discover software."),
    ("T1518.001", "Software Discovery: Security Software Discovery", "TA0007", "Adversaries may discover security software."),
    ("T1082", "System Information Discovery", "TA0007", "Adversaries may discover system information."),
    ("T1614", "System Location Discovery", "TA0007", "Adversaries may discover system location."),
    ("T1016", "System Network Configuration Discovery", "TA0007", "Adversaries may discover network configuration."),
    ("T1049", "System Network Connections Discovery", "TA0007", "Adversaries may discover network connections."),
    ("T1033", "System Owner/User Discovery", "TA0007", "Adversaries may discover system owners."),
    ("T1007", "System Service Discovery", "TA0007", "Adversaries may discover system services."),

    # ==================== LATERAL MOVEMENT (TA0008) ====================
    ("T1021", "Remote Services", "TA0008", "Adversaries may use remote services for lateral movement."),
    ("T1021.007", "Remote Services: Cloud Services", "TA0008", "Adversaries may use cloud services for lateral movement."),
    ("T1021.008", "Remote Services: Direct Cloud VM Connections", "TA0008", "Adversaries may connect directly to cloud VMs."),
    ("T1550.001", "Use Alternate Authentication: Application Access Token", "TA0008", "Adversaries may use tokens for lateral movement."),
    ("T1072", "Software Deployment Tools", "TA0008", "Adversaries may use software deployment tools."),

    # ==================== COLLECTION (TA0009) ====================
    ("T1119", "Automated Collection", "TA0009", "Adversaries may automate collection."),
    ("T1530", "Data from Cloud Storage", "TA0009", "Adversaries may access cloud storage data."),
    ("T1213", "Data from Information Repositories", "TA0009", "Adversaries may access information repositories."),
    ("T1213.003", "Data from Information Repositories: Code Repositories", "TA0009", "Adversaries may access code repositories."),
    ("T1213.006", "Data from Information Repositories: Databases", "TA0009", "Adversaries may access databases."),
    ("T1005", "Data from Local System", "TA0009", "Adversaries may collect local data."),
    ("T1074", "Data Staged", "TA0009", "Adversaries may stage collected data."),
    ("T1074.002", "Data Staged: Remote Data Staging", "TA0009", "Adversaries may stage data remotely."),

    # ==================== EXFILTRATION (TA0010) ====================
    ("T1048", "Exfiltration Over Alternative Protocol", "TA0010", "Adversaries may exfiltrate over alternative protocols."),
    ("T1048.003", "Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol", "TA0010", "Adversaries may exfiltrate over unencrypted protocols."),
    ("T1041", "Exfiltration Over C2 Channel", "TA0010", "Adversaries may exfiltrate over C2."),
    ("T1567", "Exfiltration Over Web Service", "TA0010", "Adversaries may exfiltrate over web services."),
    ("T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "TA0010", "Adversaries may exfiltrate to cloud storage."),
    ("T1537", "Transfer Data to Cloud Account", "TA0010", "Adversaries may transfer data to cloud accounts."),

    # ==================== COMMAND AND CONTROL (TA0011) ====================
    ("T1071", "Application Layer Protocol", "TA0011", "Adversaries may use application layer protocols for C2."),
    ("T1071.001", "Application Layer Protocol: Web Protocols", "TA0011", "Adversaries may use web protocols for C2."),
    ("T1071.004", "Application Layer Protocol: DNS", "TA0011", "Adversaries may use DNS for C2."),
    ("T1071.003", "Application Layer Protocol: Mail Protocols", "TA0011", "Adversaries may use mail protocols for C2."),
    ("T1090", "Proxy", "TA0011", "Adversaries may use proxies for C2."),
    ("T1090.003", "Proxy: Multi-hop Proxy", "TA0011", "Adversaries may chain proxies."),
    ("T1572", "Protocol Tunneling", "TA0011", "Adversaries may tunnel traffic."),
    ("T1571", "Non-Standard Port", "TA0011", "Adversaries may use non-standard ports."),
    ("T1568", "Dynamic Resolution", "TA0011", "Adversaries may use dynamic resolution."),
    ("T1568.002", "Dynamic Resolution: Domain Generation Algorithms", "TA0011", "Adversaries may use DGAs."),
    ("T1102", "Web Service", "TA0011", "Adversaries may use web services for C2."),
    ("T1102.002", "Web Service: Bidirectional Communication", "TA0011", "Adversaries may use web services for bidirectional C2."),

    # ==================== IMPACT (TA0040) ====================
    ("T1531", "Account Access Removal", "TA0040", "Adversaries may remove account access."),
    ("T1485", "Data Destruction", "TA0040", "Adversaries may destroy data."),
    ("T1485.001", "Data Destruction: Lifecycle-Triggered Deletion", "TA0040", "Adversaries may use lifecycle policies for deletion."),
    ("T1486", "Data Encrypted for Impact", "TA0040", "Adversaries may encrypt data for impact."),
    ("T1491", "Defacement", "TA0040", "Adversaries may deface resources."),
    ("T1491.002", "Defacement: External Defacement", "TA0040", "Adversaries may deface external resources."),
    ("T1499", "Endpoint Denial of Service", "TA0040", "Adversaries may cause endpoint DoS."),
    ("T1499.002", "Endpoint DoS: Service Exhaustion Flood", "TA0040", "Adversaries may flood services."),
    ("T1499.003", "Endpoint DoS: Application Exhaustion Flood", "TA0040", "Adversaries may flood applications."),
    ("T1499.004", "Endpoint DoS: Application or System Exploitation", "TA0040", "Adversaries may exploit for DoS."),
    ("T1490", "Inhibit System Recovery", "TA0040", "Adversaries may inhibit system recovery."),
    ("T1498", "Network Denial of Service", "TA0040", "Adversaries may cause network DoS."),
    ("T1498.001", "Network DoS: Direct Network Flood", "TA0040", "Adversaries may directly flood networks."),
    ("T1498.002", "Network DoS: Reflection Amplification", "TA0040", "Adversaries may use reflection for DoS."),
    ("T1496", "Resource Hijacking", "TA0040", "Adversaries may hijack resources."),
    ("T1496.001", "Resource Hijacking: Compute Hijacking", "TA0040", "Adversaries may hijack compute resources."),
    ("T1496.002", "Resource Hijacking: Bandwidth Hijacking", "TA0040", "Adversaries may hijack bandwidth."),
    ("T1489", "Service Stop", "TA0040", "Adversaries may stop services."),
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
