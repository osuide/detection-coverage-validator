"""GCP MITRE ATT&CK technique indicator library following 05-MAPPING-AGENT.md design.

This library maps GCP audit log methods, keywords, and patterns to MITRE techniques.
Based on MITRE ATT&CK v14.1 Cloud Matrix for GCP.
"""

from dataclasses import dataclass


@dataclass
class GCPTechniqueIndicator:
    """Indicators for a MITRE technique specific to GCP."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str

    # GCP audit log method names that indicate this technique
    audit_log_methods: list[str]

    # Keywords in detection names/descriptions
    keywords: list[str]

    # GCP services relevant to this technique
    gcp_services: list[str]

    # Log filter patterns (for Cloud Logging queries)
    log_patterns: list[str]

    # Base confidence for pattern match
    base_confidence: float = 0.7

    # Priority for gap analysis (1=critical, 4=low)
    priority: int = 2


# Discovery - TA0007
GCP_DISCOVERY_TECHNIQUES = [
    GCPTechniqueIndicator(
        technique_id="T1526",
        technique_name="Cloud Service Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        audit_log_methods=[
            "compute.instances.list",
            "compute.zones.list",
            "compute.regions.list",
            "storage.buckets.list",
            "sqladmin.instances.list",
            "cloudfunctions.functions.list",
            "container.clusters.list",
            "run.services.list",
            "iam.roles.list",
            "iam.serviceAccounts.list",
            "resourcemanager.projects.list",
        ],
        keywords=["discovery", "enumerate", "list", "describe", "inventory", "scan"],
        gcp_services=["compute", "storage", "cloudsql", "cloudfunctions", "gke", "iam"],
        log_patterns=[r"\.list$", r"\.get$", r"describe", r"inventory"],
        base_confidence=0.65,
        priority=3,
    ),
    GCPTechniqueIndicator(
        technique_id="T1580",
        technique_name="Cloud Infrastructure Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        audit_log_methods=[
            "compute.networks.list",
            "compute.subnetworks.list",
            "compute.firewalls.list",
            "compute.routes.list",
            "compute.vpnTunnels.list",
            "dns.managedZones.list",
        ],
        keywords=["network", "vpc", "firewall", "subnet", "infrastructure", "route"],
        gcp_services=["compute", "dns", "vpc"],
        log_patterns=[r"network", r"firewall", r"subnet", r"route"],
        base_confidence=0.65,
        priority=3,
    ),
    GCPTechniqueIndicator(
        technique_id="T1619",
        technique_name="Cloud Storage Object Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        audit_log_methods=[
            "storage.buckets.list",
            "storage.objects.list",
            "storage.buckets.get",
            "storage.buckets.getIamPolicy",
        ],
        keywords=["bucket", "storage", "object", "gcs", "blob"],
        gcp_services=["storage"],
        log_patterns=[r"bucket", r"storage", r"object"],
        base_confidence=0.65,
        priority=2,
    ),
]

# Initial Access - TA0001
GCP_INITIAL_ACCESS_TECHNIQUES = [
    GCPTechniqueIndicator(
        technique_id="T1078.004",
        technique_name="Valid Accounts: Cloud Accounts",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        audit_log_methods=[
            "google.login.LoginService.loginSuccess",
            "google.login.LoginService.loginFailure",
            "iam.serviceAccounts.actAs",
            "iam.serviceAccounts.getAccessToken",
            "iam.serviceAccounts.signBlob",
            "iam.serviceAccounts.signJwt",
            "sts.googleapis.com.GenerateAccessToken",
        ],
        keywords=[
            "login", "signin", "authentication", "console", "impersonate",
            "credential", "mfa", "2fa", "service account", "actAs",
        ],
        gcp_services=["iam", "sts", "cloudidentity"],
        log_patterns=[r"login", r"signin", r"actAs", r"impersonate", r"credential"],
        base_confidence=0.75,
        priority=1,
    ),
    GCPTechniqueIndicator(
        technique_id="T1199",
        technique_name="Trusted Relationship",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        audit_log_methods=[
            "iam.serviceAccounts.actAs",
            "resourcemanager.projects.setIamPolicy",
            "resourcemanager.organizations.setIamPolicy",
            "iam.roles.create",
        ],
        keywords=["cross-project", "trust", "external", "third-party", "partner", "domain"],
        gcp_services=["iam", "resourcemanager"],
        log_patterns=[r"cross.?project", r"trust", r"external", r"domain.*wide"],
        base_confidence=0.7,
        priority=2,
    ),
]

# Persistence - TA0003
GCP_PERSISTENCE_TECHNIQUES = [
    GCPTechniqueIndicator(
        technique_id="T1098",
        technique_name="Account Manipulation",
        tactic_id="TA0003",
        tactic_name="Persistence",
        audit_log_methods=[
            "iam.serviceAccounts.setIamPolicy",
            "iam.serviceAccountKeys.create",
            "iam.serviceAccountKeys.delete",
            "resourcemanager.projects.setIamPolicy",
            "cloudfunctions.functions.setIamPolicy",
            "run.services.setIamPolicy",
        ],
        keywords=[
            "account", "manipulation", "modify", "policy", "permission",
            "iam", "binding", "member", "role",
        ],
        gcp_services=["iam", "resourcemanager"],
        log_patterns=[r"setIamPolicy", r"iam", r"binding", r"permission"],
        base_confidence=0.8,
        priority=1,
    ),
    GCPTechniqueIndicator(
        technique_id="T1098.001",
        technique_name="Account Manipulation: Additional Cloud Credentials",
        tactic_id="TA0003",
        tactic_name="Persistence",
        audit_log_methods=[
            "iam.serviceAccountKeys.create",
            "iam.serviceAccountKeys.upload",
            "secretmanager.versions.add",
        ],
        keywords=[
            "service account key", "credential", "api key", "new key",
            "create key", "json key", "p12 key",
        ],
        gcp_services=["iam", "secretmanager"],
        log_patterns=[r"serviceAccountKey", r"create.*key", r"credential"],
        base_confidence=0.85,
        priority=1,
    ),
    GCPTechniqueIndicator(
        technique_id="T1098.003",
        technique_name="Account Manipulation: Additional Cloud Roles",
        tactic_id="TA0003",
        tactic_name="Persistence",
        audit_log_methods=[
            "iam.roles.create",
            "iam.roles.update",
            "iam.roles.undelete",
            "resourcemanager.projects.setIamPolicy",
            "resourcemanager.folders.setIamPolicy",
            "resourcemanager.organizations.setIamPolicy",
        ],
        keywords=["role", "custom role", "permission", "privilege", "admin", "owner"],
        gcp_services=["iam", "resourcemanager"],
        log_patterns=[r"roles?\.", r"setIamPolicy", r"privilege"],
        base_confidence=0.8,
        priority=1,
    ),
    GCPTechniqueIndicator(
        technique_id="T1136.003",
        technique_name="Create Account: Cloud Account",
        tactic_id="TA0003",
        tactic_name="Persistence",
        audit_log_methods=[
            "iam.serviceAccounts.create",
            "cloudidentity.groups.create",
            "cloudidentity.memberships.create",
        ],
        keywords=["create user", "new user", "service account", "create account"],
        gcp_services=["iam", "cloudidentity"],
        log_patterns=[r"create.*account", r"serviceAccounts\.create"],
        base_confidence=0.8,
        priority=1,
    ),
    GCPTechniqueIndicator(
        technique_id="T1525",
        technique_name="Implant Internal Image",
        tactic_id="TA0003",
        tactic_name="Persistence",
        audit_log_methods=[
            "compute.images.create",
            "compute.images.insert",
            "artifactregistry.repositories.uploadArtifact",
            "containeranalysis.occurrences.create",
        ],
        keywords=["image", "container", "artifact", "registry", "gcr", "docker"],
        gcp_services=["compute", "artifactregistry", "containerregistry"],
        log_patterns=[r"image", r"container", r"artifact", r"registry"],
        base_confidence=0.7,
        priority=2,
    ),
]

# Privilege Escalation - TA0004
GCP_PRIVILEGE_ESCALATION_TECHNIQUES = [
    GCPTechniqueIndicator(
        technique_id="T1548.005",
        technique_name="Abuse Elevation Control: Temporary Elevated Cloud Access",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        audit_log_methods=[
            "iam.serviceAccounts.actAs",
            "iam.serviceAccounts.getAccessToken",
            "sts.googleapis.com.GenerateAccessToken",
        ],
        keywords=["elevate", "escalate", "privilege", "admin", "temporary", "impersonate"],
        gcp_services=["iam", "sts"],
        log_patterns=[r"escalat", r"privilege", r"elevat", r"impersonate"],
        base_confidence=0.75,
        priority=1,
    ),
]

# Defense Evasion - TA0005
GCP_DEFENSE_EVASION_TECHNIQUES = [
    GCPTechniqueIndicator(
        technique_id="T1562.008",
        technique_name="Impair Defenses: Disable Cloud Logs",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        audit_log_methods=[
            "logging.sinks.delete",
            "logging.exclusions.create",
            "logging.logMetrics.delete",
            "logging.logs.delete",
            "securitycenter.sources.delete",
        ],
        keywords=["disable", "stop", "delete", "logging", "audit", "sink", "exclusion"],
        gcp_services=["logging", "securitycenter"],
        log_patterns=[r"delete.*log", r"disable.*log", r"exclusion"],
        base_confidence=0.85,
        priority=1,
    ),
    GCPTechniqueIndicator(
        technique_id="T1578.002",
        technique_name="Modify Cloud Compute Infrastructure: Create Snapshot",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        audit_log_methods=[
            "compute.snapshots.create",
            "compute.disks.createSnapshot",
            "sqladmin.backupRuns.insert",
        ],
        keywords=["snapshot", "backup", "copy", "disk"],
        gcp_services=["compute", "sqladmin"],
        log_patterns=[r"snapshot", r"backup"],
        base_confidence=0.6,
        priority=3,
    ),
    GCPTechniqueIndicator(
        technique_id="T1535",
        technique_name="Unused/Unsupported Cloud Regions",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        audit_log_methods=[],
        keywords=["region", "geographic", "unused", "uncommon", "location"],
        gcp_services=["compute", "cloudfunctions", "run"],
        log_patterns=[r"region", r"location"],
        base_confidence=0.5,
        priority=3,
    ),
]

# Credential Access - TA0006
GCP_CREDENTIAL_ACCESS_TECHNIQUES = [
    GCPTechniqueIndicator(
        technique_id="T1552.005",
        technique_name="Unsecured Credentials: Cloud Instance Metadata API",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        audit_log_methods=[],
        keywords=["metadata", "169.254.169.254", "metadata.google.internal", "instance identity"],
        gcp_services=["compute"],
        log_patterns=[r"metadata", r"169\.254", r"instance.*identity"],
        base_confidence=0.75,
        priority=1,
    ),
    GCPTechniqueIndicator(
        technique_id="T1528",
        technique_name="Steal Application Access Token",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        audit_log_methods=[
            "secretmanager.versions.access",
            "secretmanager.secrets.get",
            "iam.serviceAccountKeys.get",
        ],
        keywords=["secret", "token", "credential", "key", "password", "api key"],
        gcp_services=["secretmanager", "iam"],
        log_patterns=[r"secret", r"token", r"credential", r"key"],
        base_confidence=0.7,
        priority=1,
    ),
]

# Lateral Movement - TA0008
GCP_LATERAL_MOVEMENT_TECHNIQUES = [
    GCPTechniqueIndicator(
        technique_id="T1550.001",
        technique_name="Use Alternate Authentication Material: Application Access Token",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        audit_log_methods=[
            "iam.serviceAccounts.actAs",
            "sts.googleapis.com.GenerateAccessToken",
        ],
        keywords=["cross-project", "impersonate", "lateral", "token", "actAs"],
        gcp_services=["iam", "sts"],
        log_patterns=[r"actAs", r"impersonate", r"lateral", r"cross"],
        base_confidence=0.7,
        priority=2,
    ),
]

# Collection - TA0009
GCP_COLLECTION_TECHNIQUES = [
    GCPTechniqueIndicator(
        technique_id="T1530",
        technique_name="Data from Cloud Storage",
        tactic_id="TA0009",
        tactic_name="Collection",
        audit_log_methods=[
            "storage.objects.get",
            "storage.objects.copy",
            "bigquery.tables.getData",
            "bigquery.jobs.query",
        ],
        keywords=["download", "exfil", "copy", "data", "gcs", "bigquery", "bucket"],
        gcp_services=["storage", "bigquery"],
        log_patterns=[r"objects\.get", r"download", r"copy", r"getData"],
        base_confidence=0.6,
        priority=2,
    ),
]

# Exfiltration - TA0010
GCP_EXFILTRATION_TECHNIQUES = [
    GCPTechniqueIndicator(
        technique_id="T1537",
        technique_name="Transfer Data to Cloud Account",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        audit_log_methods=[
            "storage.buckets.setIamPolicy",
            "storage.objects.setIamPolicy",
            "compute.snapshots.setIamPolicy",
            "bigquery.datasets.setIamPolicy",
        ],
        keywords=["public", "share", "external", "transfer", "exfil", "allUsers", "allAuthenticatedUsers"],
        gcp_services=["storage", "compute", "bigquery"],
        log_patterns=[r"public", r"share", r"external", r"allUsers", r"allAuthenticated"],
        base_confidence=0.75,
        priority=1,
    ),
]

# Impact - TA0040
GCP_IMPACT_TECHNIQUES = [
    GCPTechniqueIndicator(
        technique_id="T1485",
        technique_name="Data Destruction",
        tactic_id="TA0040",
        tactic_name="Impact",
        audit_log_methods=[
            "storage.buckets.delete",
            "storage.objects.delete",
            "compute.instances.delete",
            "compute.disks.delete",
            "sqladmin.instances.delete",
            "bigquery.datasets.delete",
            "bigquery.tables.delete",
        ],
        keywords=["delete", "destroy", "terminate", "remove", "wipe"],
        gcp_services=["storage", "compute", "sqladmin", "bigquery"],
        log_patterns=[r"\.delete$", r"destroy", r"terminate"],
        base_confidence=0.75,
        priority=1,
    ),
    GCPTechniqueIndicator(
        technique_id="T1486",
        technique_name="Data Encrypted for Impact",
        tactic_id="TA0040",
        tactic_name="Impact",
        audit_log_methods=[
            "cloudkms.cryptoKeys.create",
            "cloudkms.cryptoKeyVersions.destroy",
            "storage.buckets.update",  # For CSEK changes
        ],
        keywords=["encrypt", "kms", "key", "csek", "cmek"],
        gcp_services=["cloudkms", "storage"],
        log_patterns=[r"encrypt", r"kms", r"key"],
        base_confidence=0.6,
        priority=2,
    ),
    GCPTechniqueIndicator(
        technique_id="T1496",
        technique_name="Resource Hijacking",
        tactic_id="TA0040",
        tactic_name="Impact",
        audit_log_methods=[
            "compute.instances.insert",
            "compute.instances.setMachineType",
            "cloudfunctions.functions.create",
            "run.services.create",
        ],
        keywords=["crypto", "mining", "hijack", "resource", "compute", "bitcoin"],
        gcp_services=["compute", "cloudfunctions", "run"],
        log_patterns=[r"crypto", r"mining", r"unusual.*compute"],
        base_confidence=0.7,
        priority=2,
    ),
]

# Execution - TA0002
GCP_EXECUTION_TECHNIQUES = [
    GCPTechniqueIndicator(
        technique_id="T1059.009",
        technique_name="Command and Scripting Interpreter: Cloud API",
        tactic_id="TA0002",
        tactic_name="Execution",
        audit_log_methods=[
            "cloudfunctions.functions.call",
            "run.jobs.run",
            "workflows.executions.create",
            "compute.instances.setMetadata",  # Startup scripts
        ],
        keywords=["execute", "invoke", "function", "cloud run", "workflow", "script"],
        gcp_services=["cloudfunctions", "run", "workflows", "compute"],
        log_patterns=[r"invoke", r"execute", r"call", r"run"],
        base_confidence=0.7,
        priority=2,
    ),
    GCPTechniqueIndicator(
        technique_id="T1648",
        technique_name="Serverless Execution",
        tactic_id="TA0002",
        tactic_name="Execution",
        audit_log_methods=[
            "cloudfunctions.functions.create",
            "cloudfunctions.functions.update",
            "cloudfunctions.functions.call",
            "run.services.create",
            "run.jobs.create",
        ],
        keywords=["cloud function", "cloud run", "serverless", "function", "invoke"],
        gcp_services=["cloudfunctions", "run"],
        log_patterns=[r"function", r"serverless", r"run\."],
        base_confidence=0.75,
        priority=2,
    ),
]


# Combine all GCP technique indicators
GCP_TECHNIQUE_INDICATORS: list[GCPTechniqueIndicator] = [
    *GCP_DISCOVERY_TECHNIQUES,
    *GCP_INITIAL_ACCESS_TECHNIQUES,
    *GCP_PERSISTENCE_TECHNIQUES,
    *GCP_PRIVILEGE_ESCALATION_TECHNIQUES,
    *GCP_DEFENSE_EVASION_TECHNIQUES,
    *GCP_CREDENTIAL_ACCESS_TECHNIQUES,
    *GCP_LATERAL_MOVEMENT_TECHNIQUES,
    *GCP_COLLECTION_TECHNIQUES,
    *GCP_EXFILTRATION_TECHNIQUES,
    *GCP_IMPACT_TECHNIQUES,
    *GCP_EXECUTION_TECHNIQUES,
]

# Create lookup dictionaries for efficient access
GCP_TECHNIQUE_BY_ID: dict[str, GCPTechniqueIndicator] = {
    t.technique_id: t for t in GCP_TECHNIQUE_INDICATORS
}

GCP_TECHNIQUES_BY_TACTIC: dict[str, list[GCPTechniqueIndicator]] = {}
for t in GCP_TECHNIQUE_INDICATORS:
    if t.tactic_id not in GCP_TECHNIQUES_BY_TACTIC:
        GCP_TECHNIQUES_BY_TACTIC[t.tactic_id] = []
    GCP_TECHNIQUES_BY_TACTIC[t.tactic_id].append(t)

GCP_AUDIT_METHOD_TO_TECHNIQUES: dict[str, list[str]] = {}
for t in GCP_TECHNIQUE_INDICATORS:
    for method in t.audit_log_methods:
        if method not in GCP_AUDIT_METHOD_TO_TECHNIQUES:
            GCP_AUDIT_METHOD_TO_TECHNIQUES[method] = []
        GCP_AUDIT_METHOD_TO_TECHNIQUES[method].append(t.technique_id)
