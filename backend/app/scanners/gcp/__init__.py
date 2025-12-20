"""GCP detection scanners."""

from app.scanners.gcp.cloud_logging_scanner import CloudLoggingScanner
from app.scanners.gcp.security_command_center_scanner import (
    SecurityCommandCenterScanner,
)
from app.scanners.gcp.eventarc_scanner import EventarcScanner

# Organisation-level scanners
from app.scanners.gcp.org_log_sink_scanner import (
    OrgLogSinkScanner,
    OrgLogBucketScanner,
)
from app.scanners.gcp.org_policy_scanner import (
    OrgPolicyScanner,
    EffectiveOrgPolicyScanner,
)
from app.scanners.gcp.org_scc_scanner import (
    OrgSecurityCommandCenterScanner,
    SCCSecurityPostureScanner,
)
from app.scanners.gcp.org_chronicle_scanner import (
    OrgChronicleScanner,
    ChronicleRuleAlertsScanner,
)
from app.scanners.gcp.scc_findings_scanner import (
    SCCFindingsScanner,
    SCCModuleStatusScanner,
)

__all__ = [
    # Project-level scanners
    "CloudLoggingScanner",
    "SecurityCommandCenterScanner",
    "EventarcScanner",
    # Organisation-level scanners
    "OrgLogSinkScanner",
    "OrgLogBucketScanner",
    "OrgPolicyScanner",
    "EffectiveOrgPolicyScanner",
    "OrgSecurityCommandCenterScanner",
    "SCCSecurityPostureScanner",
    "OrgChronicleScanner",
    "ChronicleRuleAlertsScanner",
    # SCC Premium findings scanners
    "SCCFindingsScanner",
    "SCCModuleStatusScanner",
]
