"""
Template Loader - Loads and manages remediation templates.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
from enum import Enum


class DetectionType(str, Enum):
    # AWS
    GUARDDUTY = "guardduty"
    CLOUDWATCH_QUERY = "cloudwatch_query"
    EVENTBRIDGE_RULE = "eventbridge_rule"
    CONFIG_RULE = "config_rule"
    SECURITY_HUB = "security_hub"
    CUSTOM_LAMBDA = "custom_lambda"
    # GCP
    SECURITY_COMMAND_CENTER = "security_command_center"
    CLOUD_LOGGING_QUERY = "cloud_logging_query"
    EVENTARC = "eventarc"
    CLOUD_FUNCTIONS = "cloud_functions"


class EffortLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FalsePositiveRate(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class Campaign:
    """Real-world campaign using this technique."""
    name: str
    year: int
    description: str
    reference_url: Optional[str] = None


@dataclass
class ThreatContext:
    """Adversarial context for a technique."""
    description: str
    attacker_goal: str
    why_technique: List[str]
    known_threat_actors: List[str]
    recent_campaigns: List[Campaign]
    prevalence: str  # common, moderate, rare
    trend: str  # increasing, stable, decreasing
    severity_score: int  # 1-10
    severity_reasoning: str
    business_impact: List[str]
    typical_attack_phase: str
    often_precedes: List[str] = field(default_factory=list)
    often_follows: List[str] = field(default_factory=list)


@dataclass
class DetectionImplementation:
    """Actual implementation artefacts for a detection."""
    # Queries
    query: Optional[str] = None  # AWS CloudWatch Logs Insights
    gcp_logging_query: Optional[str] = None  # GCP Cloud Logging
    # AWS-specific
    event_pattern: Optional[Dict[str, Any]] = None
    guardduty_finding_types: Optional[List[str]] = None
    config_rule_identifier: Optional[str] = None
    cloudformation_template: Optional[str] = None
    # GCP-specific
    scc_finding_categories: Optional[List[str]] = None  # Security Command Center
    gcp_terraform_template: Optional[str] = None
    # Shared
    terraform_template: Optional[str] = None  # AWS Terraform (legacy field)
    alert_severity: str = "medium"
    alert_title: str = ""
    alert_description_template: str = ""
    investigation_steps: List[str] = field(default_factory=list)
    containment_actions: List[str] = field(default_factory=list)


class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"


@dataclass
class DetectionStrategy:
    """Single detection approach for a technique."""
    strategy_id: str
    name: str
    description: str
    detection_type: DetectionType
    aws_service: str  # Keep for backwards compatibility
    implementation: DetectionImplementation
    estimated_false_positive_rate: FalsePositiveRate
    false_positive_tuning: str
    detection_coverage: str
    evasion_considerations: str
    implementation_effort: EffortLevel
    implementation_time: str
    estimated_monthly_cost: str
    prerequisites: List[str] = field(default_factory=list)
    cloud_provider: CloudProvider = CloudProvider.AWS  # Default to AWS
    gcp_service: Optional[str] = None  # e.g., "security_command_center", "cloud_logging"


@dataclass
class RemediationTemplate:
    """Complete remediation guidance for a MITRE technique."""
    technique_id: str
    technique_name: str
    tactic_ids: List[str]
    mitre_url: str
    threat_context: ThreatContext
    detection_strategies: List[DetectionStrategy]
    recommended_order: List[str]
    total_effort_hours: float
    coverage_improvement: str
    last_updated: str = "2025-12-19"
    version: str = "1.0"


# Import all templates
from .t1078_001_default_accounts import TEMPLATE as T1078_001
from .t1078_004_cloud_accounts import TEMPLATE as T1078_004
from .t1110_brute_force import TEMPLATE as T1110
from .t1562_001_disable_security_tools import TEMPLATE as T1562_001
from .t1530_data_from_cloud_storage import TEMPLATE as T1530
from .t1098_account_manipulation import TEMPLATE as T1098
from .t1552_unsecured_credentials import TEMPLATE as T1552
from .t1552_001_credentials_in_files import TEMPLATE as T1552_001
from .t1552_005_cloud_instance_metadata import TEMPLATE as T1552_005
from .t1528_steal_app_access_token import TEMPLATE as T1528
from .t1537_transfer_data_cloud_account import TEMPLATE as T1537
from .t1562_008_disable_cloud_logs import TEMPLATE as T1562_008
from .t1098_001_additional_cloud_credentials import TEMPLATE as T1098_001
from .t1098_003_additional_cloud_roles import TEMPLATE as T1098_003
from .t1136_003_create_cloud_account import TEMPLATE as T1136_003
from .t1087_004_cloud_account_discovery import TEMPLATE as T1087_004
from .t1069_003_cloud_groups_discovery import TEMPLATE as T1069_003
from .t1069_permission_groups_discovery import TEMPLATE as T1069
from .t1580_cloud_infrastructure_discovery import TEMPLATE as T1580
from .t1578_001_create_snapshot import TEMPLATE as T1578_001
from .t1526_cloud_service_discovery import TEMPLATE as T1526
from .t1619_cloud_storage_object_discovery import TEMPLATE as T1619
from .t1578_002_create_cloud_instance import TEMPLATE as T1578_002
from .t1578_003_delete_cloud_instance import TEMPLATE as T1578_003
from .t1535_unused_cloud_regions import TEMPLATE as T1535
from .t1621_mfa_request_generation import TEMPLATE as T1621
from .t1496_001_compute_hijacking import TEMPLATE as T1496_001
from .t1496_002_bandwidth_hijacking import TEMPLATE as T1496_002
from .t1555_006_cloud_secrets import TEMPLATE as T1555_006
from .t1648_serverless_execution import TEMPLATE as T1648
from .t1651_cloud_admin_command import TEMPLATE as T1651
from .t1485_data_destruction import TEMPLATE as T1485
from .t1486_data_encrypted_for_impact import TEMPLATE as T1486
from .t1657_financial_theft import TEMPLATE as T1657
from .t1190_exploit_public_facing_app import TEMPLATE as T1190
from .t1525_implant_internal_image import TEMPLATE as T1525
from .t1531_account_access_removal import TEMPLATE as T1531
from .t1204_003_malicious_image import TEMPLATE as T1204_003
from .t1114_email_collection import TEMPLATE as T1114
from .t1114_003_email_forwarding_rule import TEMPLATE as T1114_003
from .t1021_007_cloud_services import TEMPLATE as T1021_007
from .t1021_remote_services import TEMPLATE as T1021
from .t1489_service_stop import TEMPLATE as T1489
from .t1567_exfil_web_service import TEMPLATE as T1567
from .t1567_001_exfil_code_repo import TEMPLATE as T1567_001
from .t1567_002_exfil_cloud_storage import TEMPLATE as T1567_002
from .t1567_003_exfil_text_storage import TEMPLATE as T1567_003
from .t1573_encrypted_channel import TEMPLATE as T1573
from .t1550_use_alternate_auth import TEMPLATE as T1550
from .t1550_002_pass_the_hash import TEMPLATE as T1550_002
from .t1550_003_pass_the_ticket import TEMPLATE as T1550_003
from .t1606_forge_web_credentials import TEMPLATE as T1606
from .t1059_009_cloud_api import TEMPLATE as T1059_009
from .t1538_cloud_service_dashboard import TEMPLATE as T1538
from .t1556_modify_auth_process import TEMPLATE as T1556
from .t1556_006_mfa_modification import TEMPLATE as T1556_006
from .t1556_009_conditional_access_policies import TEMPLATE as T1556_009
from .t1609_container_admin_command import TEMPLATE as T1609
from .t1610_deploy_container import TEMPLATE as T1610
from .t1611_escape_to_host import TEMPLATE as T1611
from .t1612_build_image_on_host import TEMPLATE as T1612
from .t1613_container_resource_discovery import TEMPLATE as T1613
from .t1040_network_sniffing import TEMPLATE as T1040
from .t1557_adversary_in_the_middle import TEMPLATE as T1557
from .t1557_002_arp_poisoning import TEMPLATE as T1557_002
from .t1003_credential_dumping import TEMPLATE as T1003
from .t1195_003_compromise_hardware import TEMPLATE as T1195_003
from .t1199_trusted_relationship import TEMPLATE as T1199
from .t1200_hardware_additions import TEMPLATE as T1200
from .t1048_exfil_alt_protocol import TEMPLATE as T1048
from .t1105_ingress_tool_transfer import TEMPLATE as T1105
from .t1518_software_discovery import TEMPLATE as T1518
from .t1057_process_discovery import TEMPLATE as T1057
from .t1027_obfuscated_files import TEMPLATE as T1027
from .t1070_indicator_removal import TEMPLATE as T1070
from .t1071_application_layer_protocol import TEMPLATE as T1071
from .t1071_004_dns import TEMPLATE as T1071_004
from .t1072_software_deployment_tools import TEMPLATE as T1072
from .t1007_system_service_discovery import TEMPLATE as T1007
from .t1033_system_owner_discovery import TEMPLATE as T1033
from .t1134_access_token_manipulation import TEMPLATE as T1134
from .t1112_modify_registry import TEMPLATE as T1112
from .t1497_001_system_checks import TEMPLATE as T1497_001
from .t1497_virtualization_sandbox_evasion import TEMPLATE as T1497
from .t1074_data_staged import TEMPLATE as T1074
from .t1548_abuse_elevation import TEMPLATE as T1548
from .t1547_boot_logon_autostart import TEMPLATE as T1547
from .t1083_file_directory_discovery import TEMPLATE as T1083
from .t1036_masquerading import TEMPLATE as T1036
from .t1566_phishing import TEMPLATE as T1566
from .t1564_hide_artifacts import TEMPLATE as T1564

from .t1124_system_time_discovery import TEMPLATE as T1124
from .t1102_web_service import TEMPLATE as T1102
from .t1189_driveby_compromise import TEMPLATE as T1189
from .t1195_supply_chain_compromise import TEMPLATE as T1195
from .t1560_archive_collected_data import TEMPLATE as T1560
from .t1055_process_injection import TEMPLATE as T1055
from .t1091_removable_media import TEMPLATE as T1091
from .t1133_external_remote_services import TEMPLATE as T1133
from .t1095_non_app_layer_protocol import TEMPLATE as T1095
from .t1008_fallback_channels import TEMPLATE as T1008
from .t1219_remote_access_software import TEMPLATE as T1219
from .t1187_forced_authentication import TEMPLATE as T1187
from .t1221_template_injection import TEMPLATE as T1221
from .t1491_001_internal_defacement import TEMPLATE as T1491_001
from .t1491_defacement import TEMPLATE as T1491
from .t1505_server_software_component import TEMPLATE as T1505
from .t1565_001_stored_data_manipulation import TEMPLATE as T1565_001
from .t1029_scheduled_transfer import TEMPLATE as T1029
from .t1572_protocol_tunneling import TEMPLATE as T1572
from .t1559_inter_process_comm import TEMPLATE as T1559
from .t1098_005_device_registration import TEMPLATE as T1098_005

from .t1030_data_transfer_size_limits import TEMPLATE as T1030
from .t1020_automated_exfiltration import TEMPLATE as T1020
from .t1203_exploitation_client_exec import TEMPLATE as T1203
from .t1210_exploitation_remote_services import TEMPLATE as T1210
from .t1059_command_scripting import TEMPLATE as T1059
from .t1570_lateral_tool_transfer import TEMPLATE as T1570
from .t1217_browser_info_discovery import TEMPLATE as T1217
from .t1127_trusted_dev_utils import TEMPLATE as T1127
from .t1005_data_local_system import TEMPLATE as T1005
from .t1123_audio_capture import TEMPLATE as T1123
from .t1125_video_capture import TEMPLATE as T1125
from .t1119_automated_collection import TEMPLATE as T1119
from .t1115_clipboard_data import TEMPLATE as T1115

# Additional imports - batch 1 (discovery, exfiltration, persistence)
from .t1001_data_obfuscation import TEMPLATE as T1001
from .t1010_app_window_discovery import TEMPLATE as T1010
from .t1011_exfil_other_network import TEMPLATE as T1011
from .t1012_query_registry import TEMPLATE as T1012
from .t1016_network_config_discovery import TEMPLATE as T1016
from .t1018_remote_system_discovery import TEMPLATE as T1018
from .t1025_data_removable_media import TEMPLATE as T1025
from .t1039_data_network_shared_drive import TEMPLATE as T1039
from .t1041_exfil_over_c2 import TEMPLATE as T1041
from .t1046_network_service_discovery import TEMPLATE as T1046
from .t1047_wmi import TEMPLATE as T1047
from .t1048_002_exfil_asymmetric_encrypted import TEMPLATE as T1048_002
from .t1048_003_exfil_unencrypted import TEMPLATE as T1048_003
from .t1049_network_connections_discovery import TEMPLATE as T1049
from .t1052_exfil_physical_medium import TEMPLATE as T1052
from .t1053_scheduled_task import TEMPLATE as T1053
from .t1056_input_capture import TEMPLATE as T1056
from .t1078_valid_accounts import TEMPLATE as T1078
from .t1080_taint_shared_content import TEMPLATE as T1080
from .t1082_system_info_discovery import TEMPLATE as T1082
from .t1087_account_discovery import TEMPLATE as T1087
from .t1090_proxy import TEMPLATE as T1090
from .t1098_004_ssh_authorized_keys import TEMPLATE as T1098_004
from .t1104_multi_stage_channels import TEMPLATE as T1104
from .t1106_native_api import TEMPLATE as T1106
from .t1111_mfa_interception import TEMPLATE as T1111
from .t1113_screen_capture import TEMPLATE as T1113
from .t1120_peripheral_device_discovery import TEMPLATE as T1120
from .t1132_data_encoding import TEMPLATE as T1132
from .t1136_create_account import TEMPLATE as T1136
from .t1137_office_app_startup import TEMPLATE as T1137
from .t1140_deobfuscate_decode import TEMPLATE as T1140
from .t1176_browser_extensions import TEMPLATE as T1176
from .t1197_bits_jobs import TEMPLATE as T1197
from .t1202_indirect_command_exec import TEMPLATE as T1202
from .t1204_user_execution import TEMPLATE as T1204
from .t1212_exploitation_credential_access import TEMPLATE as T1212
from .t1213_data_info_repositories import TEMPLATE as T1213
from .t1213_003_code_repositories import TEMPLATE as T1213_003
from .t1220_xsl_script_processing import TEMPLATE as T1220
from .t1480_execution_guardrails import TEMPLATE as T1480
from .t1490_inhibit_system_recovery import TEMPLATE as T1490
from .t1491_002_external_defacement import TEMPLATE as T1491_002
from .t1498_network_dos import TEMPLATE as T1498
from .t1499_endpoint_dos import TEMPLATE as T1499
from .t1499_004_application_exploitation import TEMPLATE as T1499_004
from .t1529_system_shutdown_reboot import TEMPLATE as T1529
from .t1534_internal_spearphishing import TEMPLATE as T1534
from .t1539_steal_web_session_cookie import TEMPLATE as T1539
from .t1542_pre_os_boot import TEMPLATE as T1542
from .t1543_create_modify_system_process import TEMPLATE as T1543
from .t1546_event_triggered_execution import TEMPLATE as T1546
from .t1550_001_app_access_token import TEMPLATE as T1550_001
from .t1550_004_web_session_cookie import TEMPLATE as T1550_004
from .t1554_compromise_host_software import TEMPLATE as T1554
from .t1555_credentials_password_stores import TEMPLATE as T1555
from .t1557_001_llmnr_poisoning import TEMPLATE as T1557_001
from .t1557_003_dhcp_spoofing import TEMPLATE as T1557_003
from .t1558_kerberos_tickets import TEMPLATE as T1558
from .t1561_disk_wipe import TEMPLATE as T1561
from .t1562_impair_defenses import TEMPLATE as T1562
from .t1565_data_manipulation import TEMPLATE as T1565
from .t1567_004_exfil_webhook import TEMPLATE as T1567_004
from .t1568_dynamic_resolution import TEMPLATE as T1568
from .t1569_system_services import TEMPLATE as T1569
from .t1571_non_standard_port import TEMPLATE as T1571
from .t1574_hijack_execution_flow import TEMPLATE as T1574
from .t1578_modify_cloud_compute import TEMPLATE as T1578
from .t1614_system_location_discovery import TEMPLATE as T1614
from .t1622_debugger_evasion import TEMPLATE as T1622
from .t1666_modify_cloud_resource_hierarchy import TEMPLATE as T1666
from .t1027_006_html_smuggling import TEMPLATE as T1027_006
from .t1608_stage_capabilities import TEMPLATE as T1608

# New template imports - batch 2
from .t1021_008_direct_cloud_vm_connections import TEMPLATE as T1021_008
from .t1048_001_exfil_symmetric_encrypted import TEMPLATE as T1048_001
from .t1068_exploitation_for_privilege_escalation import TEMPLATE as T1068
from .t1071_001_web_protocols import TEMPLATE as T1071_001
from .t1071_003_mail_protocols import TEMPLATE as T1071_003
from .t1074_002_remote_data_staging import TEMPLATE as T1074_002
from .t1090_003_multi_hop_proxy import TEMPLATE as T1090_003
from .t1098_006_additional_container_cluster_roles import TEMPLATE as T1098_006
from .t1102_002_bidirectional_communication import TEMPLATE as T1102_002
from .t1110_001_password_guessing import TEMPLATE as T1110_001
from .t1110_003_password_spraying import TEMPLATE as T1110_003
from .t1110_004_credential_stuffing import TEMPLATE as T1110_004
from .t1135_network_share_discovery import TEMPLATE as T1135
from .t1201_password_policy_discovery import TEMPLATE as T1201
from .t1204_001_malicious_link import TEMPLATE as T1204_001
from .t1204_002_malicious_file import TEMPLATE as T1204_002
from .t1211_exploitation_for_defense_evasion import TEMPLATE as T1211
from .t1213_006_databases import TEMPLATE as T1213_006
from .t1485_001_cloud_storage_deletion import TEMPLATE as T1485_001
from .t1496_resource_hijacking import TEMPLATE as T1496
from .t1498_001_direct_network_flood import TEMPLATE as T1498_001
from .t1498_002_reflection_amplification import TEMPLATE as T1498_002
from .t1499_002_service_exhaustion_flood import TEMPLATE as T1499_002
from .t1499_003_application_exhaustion_flood import TEMPLATE as T1499_003
from .t1518_001_security_software_discovery import TEMPLATE as T1518_001
from .t1546_008_accessibility_features import TEMPLATE as T1546_008
from .t1548_005_temporary_elevated_cloud_access import TEMPLATE as T1548_005
from .t1552_007_container_api import TEMPLATE as T1552_007
from .t1556_007_hybrid_identity import TEMPLATE as T1556_007
from .t1562_007_disable_cloud_firewall import TEMPLATE as T1562_007
from .t1566_001_spearphishing_attachment import TEMPLATE as T1566_001
from .t1566_002_spearphishing_link import TEMPLATE as T1566_002
from .t1568_002_domain_generation_algorithms import TEMPLATE as T1568_002
from .t1578_004_revert_cloud_instance import TEMPLATE as T1578_004
from .t1578_005_modify_cloud_compute_config import TEMPLATE as T1578_005
from .t1583_006_web_services import TEMPLATE as T1583_006
from .t1583_acquire_infrastructure import TEMPLATE as T1583
from .t1584_compromise_infrastructure import TEMPLATE as T1584
from .t1585_establish_accounts import TEMPLATE as T1585
from .t1586_003_cloud_accounts import TEMPLATE as T1586_003
from .t1586_compromise_accounts import TEMPLATE as T1586
from .t1587_develop_capabilities import TEMPLATE as T1587
from .t1588_002_tool import TEMPLATE as T1588_002
from .t1588_obtain_capabilities import TEMPLATE as T1588
from .t1589_gather_victim_identity import TEMPLATE as T1589
from .t1590_gather_victim_network_info import TEMPLATE as T1590
from .t1591_gather_victim_org_info import TEMPLATE as T1591
from .t1592_gather_victim_host_info import TEMPLATE as T1592
from .t1593_search_open_websites import TEMPLATE as T1593
from .t1594_search_victim_owned_websites import TEMPLATE as T1594
from .t1595_001_scanning_ip_blocks import TEMPLATE as T1595_001
from .t1595_002_vulnerability_scanning import TEMPLATE as T1595_002
from .t1595_003_wordlist_scanning import TEMPLATE as T1595_003
from .t1595_active_scanning import TEMPLATE as T1595
from .t1596_search_open_technical_databases import TEMPLATE as T1596
from .t1597_search_closed_sources import TEMPLATE as T1597
from .t1598_phishing_for_information import TEMPLATE as T1598
from .t1606_001_web_cookies import TEMPLATE as T1606_001
from .t1606_002_saml_tokens import TEMPLATE as T1606_002
from .t1620_reflective_code_loading import TEMPLATE as T1620
from .t1654_log_enumeration import TEMPLATE as T1654
from .t1667_email_bombing import TEMPLATE as T1667
from .t1680_local_storage_discovery import TEMPLATE as T1680

# Template registry
TEMPLATES: Dict[str, RemediationTemplate] = {
    "T1078.001": T1078_001,
    "T1078.004": T1078_004,
    "T1110": T1110,
    "T1562.001": T1562_001,
    "T1530": T1530,
    "T1098": T1098,
    "T1552": T1552,
    "T1552.001": T1552_001,
    "T1552.005": T1552_005,
    "T1528": T1528,
    "T1537": T1537,
    "T1562.008": T1562_008,
    "T1098.001": T1098_001,
    "T1098.003": T1098_003,
    "T1098.005": T1098_005,
    "T1136.003": T1136_003,
    "T1087.004": T1087_004,
    "T1069": T1069,
    "T1069.003": T1069_003,
    "T1580": T1580,
    "T1578.001": T1578_001,
    "T1526": T1526,
    "T1619": T1619,
    "T1578.002": T1578_002,
    "T1535": T1535,
    "T1621": T1621,
    "T1496.001": T1496_001,
    "T1496.002": T1496_002,
    "T1555.006": T1555_006,
    "T1648": T1648,
    "T1651": T1651,
    "T1485": T1485,
    "T1486": T1486,
    "T1657": T1657,
    "T1190": T1190,
    "T1525": T1525,
    "T1531": T1531,
    "T1204.003": T1204_003,
    "T1114": T1114,
    "T1114.003": T1114_003,
    "T1127": T1127,
    "T1021.007": T1021_007,
    "T1021": T1021,
    "T1489": T1489,
    "T1491": T1491,
    "T1567": T1567,
    "T1567.002": T1567_002,
    "T1567.001": T1567_001,
    "T1567.003": T1567_003,
    "T1573": T1573,
    "T1550": T1550,
    "T1550.002": T1550_002,
    "T1550.003": T1550_003,
    "T1606": T1606,
    "T1059": T1059,

    "T1059.009": T1059_009,
    "T1538": T1538,
    "T1556": T1556,
    "T1556.006": T1556_006,
    "T1556.009": T1556_009,
    "T1609": T1609,
    "T1610": T1610,
    "T1611": T1611,
    "T1612": T1612,
    "T1613": T1613,
    "T1040": T1040,
    "T1003": T1003,
    "T1195": T1195,
    "T1195.003": T1195_003,
    "T1199": T1199,
    "T1200": T1200,
    "T1557": T1557,
    "T1557.002": T1557_002,
    "T1048": T1048,
    "T1105": T1105,
    "T1518": T1518,
    "T1057": T1057,
    "T1070": T1070,
    "T1027": T1027,
    "T1027.006": T1027_006,
    "T1071": T1071,
    "T1071.004": T1071_004,
    "T1072": T1072,
    "T1007": T1007,
    "T1033": T1033,
    "T1134": T1134,
    "T1112": T1112,
    "T1548": T1548,
    "T1547": T1547,
    "T1074": T1074,
    "T1005": T1005,
    "T1560": T1560,
    "T1083": T1083,
    "T1497.001": T1497_001,
    "T1497": T1497,
    "T1566": T1566,
    "T1189": T1189,
    "T1203": T1203,
    "T1210": T1210,
    "T1564": T1564,
    "T1124": T1124,
    "T1102": T1102,
    "T1055": T1055,
    "T1091": T1091,
    "T1133": T1133,
    "T1008": T1008,
    "T1036": T1036,
    "T1020": T1020,
    "T1030": T1030,
    "T1029": T1029,
    "T1095": T1095,
    "T1187": T1187,
    "T1217": T1217,
    "T1219": T1219,
    "T1221": T1221,
    "T1491.001": T1491_001,
    "T1572": T1572,
    "T1565.001": T1565_001,
    "T1505": T1505,
    "T1559": T1559,
    "T1570": T1570,
    "T1123": T1123,
    "T1125": T1125,
    "T1119": T1119,
    "T1115": T1115,
    # Batch 1 additions
    "T1001": T1001,
    "T1010": T1010,
    "T1011": T1011,
    "T1012": T1012,
    "T1016": T1016,
    "T1018": T1018,
    "T1025": T1025,
    "T1039": T1039,
    "T1041": T1041,
    "T1046": T1046,
    "T1047": T1047,
    "T1048.002": T1048_002,
    "T1048.003": T1048_003,
    "T1049": T1049,
    "T1052": T1052,
    "T1053": T1053,
    "T1056": T1056,
    "T1078": T1078,
    "T1080": T1080,
    "T1082": T1082,
    "T1087": T1087,
    "T1090": T1090,
    "T1098.004": T1098_004,
    "T1104": T1104,
    "T1106": T1106,
    "T1111": T1111,
    "T1113": T1113,
    "T1120": T1120,
    "T1132": T1132,
    "T1136": T1136,
    "T1137": T1137,
    "T1140": T1140,
    "T1176": T1176,
    "T1197": T1197,
    "T1202": T1202,
    "T1204": T1204,
    "T1212": T1212,
    "T1213": T1213,
    "T1213.003": T1213_003,
    "T1220": T1220,
    "T1480": T1480,
    "T1490": T1490,
    "T1491.002": T1491_002,
    "T1498": T1498,
    "T1499": T1499,
    "T1499.004": T1499_004,
    "T1529": T1529,
    "T1534": T1534,
    "T1539": T1539,
    "T1542": T1542,
    "T1543": T1543,
    "T1546": T1546,
    "T1550.001": T1550_001,
    "T1550.004": T1550_004,
    "T1554": T1554,
    "T1555": T1555,
    "T1557.001": T1557_001,
    "T1557.003": T1557_003,
    "T1558": T1558,
    "T1561": T1561,
    "T1562": T1562,
    "T1565": T1565,
    "T1567.004": T1567_004,
    "T1568": T1568,
    "T1569": T1569,
    "T1571": T1571,
    "T1574": T1574,
    "T1578": T1578,
    "T1608": T1608,
    "T1614": T1614,
    "T1622": T1622,
    "T1666": T1666,
    # Batch 2 additions
    "T1021.008": T1021_008,
    "T1048.001": T1048_001,
    "T1068": T1068,
    "T1071.001": T1071_001,
    "T1071.003": T1071_003,
    "T1074.002": T1074_002,
    "T1090.003": T1090_003,
    "T1098.006": T1098_006,
    "T1102.002": T1102_002,
    "T1110.001": T1110_001,
    "T1110.003": T1110_003,
    "T1110.004": T1110_004,
    "T1135": T1135,
    "T1201": T1201,
    "T1204.001": T1204_001,
    "T1204.002": T1204_002,
    "T1211": T1211,
    "T1213.006": T1213_006,
    "T1485.001": T1485_001,
    "T1496": T1496,
    "T1498.001": T1498_001,
    "T1498.002": T1498_002,
    "T1499.002": T1499_002,
    "T1499.003": T1499_003,
    "T1518.001": T1518_001,
    "T1546.008": T1546_008,
    "T1548.005": T1548_005,
    "T1552.007": T1552_007,
    "T1556.007": T1556_007,
    "T1562.007": T1562_007,
    "T1566.001": T1566_001,
    "T1566.002": T1566_002,
    "T1568.002": T1568_002,
    "T1578.003": T1578_003,
    "T1578.004": T1578_004,
    "T1578.005": T1578_005,
    "T1583": T1583,
    "T1583.006": T1583_006,
    "T1584": T1584,
    "T1585": T1585,
    "T1586": T1586,
    "T1586.003": T1586_003,
    "T1587": T1587,
    "T1588": T1588,
    "T1588.002": T1588_002,
    "T1589": T1589,
    "T1590": T1590,
    "T1591": T1591,
    "T1592": T1592,
    "T1593": T1593,
    "T1594": T1594,
    "T1595": T1595,
    "T1595.001": T1595_001,
    "T1595.002": T1595_002,
    "T1595.003": T1595_003,
    "T1596": T1596,
    "T1597": T1597,
    "T1598": T1598,
    "T1606.001": T1606_001,
    "T1606.002": T1606_002,
    "T1620": T1620,
    "T1654": T1654,
    "T1667": T1667,
    "T1680": T1680,
}

# Parent technique mappings (for sub-techniques)
PARENT_MAPPINGS = {
    "T1078.001": "T1078",
    "T1078.004": "T1078",
    "T1562.001": "T1562",
    "T1562.008": "T1562",
    "T1552.001": "T1552",
    "T1552.005": "T1552",
    "T1098.001": "T1098",
    "T1098.003": "T1098",
    "T1098.005": "T1098",
    "T1136.003": "T1136",
    "T1087.004": "T1087",
    "T1069.003": "T1069",
    "T1578.001": "T1578",
    "T1578.002": "T1578",
    "T1496.001": "T1496",
    "T1555.006": "T1555",
    "T1556.006": "T1556",
    "T1556.009": "T1556",
    "T1204.003": "T1204",
    "T1114.003": "T1114",
    "T1021.007": "T1021",
    "T1059.009": "T1059",
    "T1195.003": "T1195",
    "T1497.001": "T1497",
    "T1491.001": "T1491",
    "T1565.001": "T1565",
    "T1567.001": "T1567",
    "T1567.002": "T1567",
    "T1557.002": "T1557",
    "T1567.003": "T1567",
    "T1550.002": "T1550",
    "T1550.003": "T1550",
    "T1213.003": "T1213",
    # Additional parent mappings
    "T1048.002": "T1048",
    "T1048.003": "T1048",
    "T1098.004": "T1098",
    "T1491.002": "T1491",
    "T1550.001": "T1550",
    "T1550.004": "T1550",
    "T1557.001": "T1557",
    "T1557.003": "T1557",
    "T1567.004": "T1567",
    "T1027.006": "T1027",
    # Batch 2 parent mappings
    "T1021.008": "T1021",
    "T1048.001": "T1048",
    "T1071.001": "T1071",
    "T1071.003": "T1071",
    "T1074.002": "T1074",
    "T1090.003": "T1090",
    "T1098.006": "T1098",
    "T1102.002": "T1102",
    "T1110.001": "T1110",
    "T1110.003": "T1110",
    "T1110.004": "T1110",
    "T1204.001": "T1204",
    "T1204.002": "T1204",
    "T1213.006": "T1213",
    "T1485.001": "T1485",
    "T1498.001": "T1498",
    "T1498.002": "T1498",
    "T1499.002": "T1499",
    "T1499.003": "T1499",
    "T1518.001": "T1518",
    "T1546.008": "T1546",
    "T1548.005": "T1548",
    "T1552.007": "T1552",
    "T1556.007": "T1556",
    "T1562.007": "T1562",
    "T1566.001": "T1566",
    "T1566.002": "T1566",
    "T1568.002": "T1568",
    "T1578.003": "T1578",
    "T1578.004": "T1578",
    "T1578.005": "T1578",
    "T1583.006": "T1583",
    "T1586.003": "T1586",
    "T1588.002": "T1588",
    "T1595.001": "T1595",
    "T1595.002": "T1595",
    "T1595.003": "T1595",
    "T1606.001": "T1606",
    "T1606.002": "T1606",
    "T1496.002": "T1496",
}


def get_template(technique_id: str) -> Optional[RemediationTemplate]:
    """
    Get remediation template for a technique.

    Falls back to parent technique if sub-technique not found.
    """
    # Direct match
    if technique_id in TEMPLATES:
        return TEMPLATES[technique_id]

    # Try parent technique
    if "." in technique_id:
        parent_id = technique_id.split(".")[0]
        if parent_id in TEMPLATES:
            return TEMPLATES[parent_id]

    return None


def get_all_templates() -> Dict[str, RemediationTemplate]:
    """Get all available templates."""
    return TEMPLATES.copy()


def get_templates_by_tactic(tactic_id: str) -> List[RemediationTemplate]:
    """Get all templates for a specific tactic."""
    return [
        template for template in TEMPLATES.values()
        if tactic_id in template.tactic_ids
    ]
