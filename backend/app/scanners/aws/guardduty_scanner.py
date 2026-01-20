"""AWS GuardDuty scanner for managed threat detection findings."""

from typing import Any, Optional
from botocore.exceptions import ClientError

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection

# GuardDuty feature names as returned by the API
# See: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-features-activation-model.html
FEATURE_S3_DATA_EVENTS = "S3_DATA_EVENTS"
FEATURE_EKS_AUDIT_LOGS = "EKS_AUDIT_LOGS"
FEATURE_EBS_MALWARE_PROTECTION = "EBS_MALWARE_PROTECTION"
FEATURE_RDS_LOGIN_EVENTS = "RDS_LOGIN_EVENTS"
FEATURE_LAMBDA_NETWORK_LOGS = "LAMBDA_NETWORK_LOGS"
FEATURE_RUNTIME_MONITORING = "RUNTIME_MONITORING"
# Foundational features (read-only, always enabled with detector)
FEATURE_FLOW_LOGS = "FLOW_LOGS"
FEATURE_DNS_LOGS = "DNS_LOGS"
FEATURE_CLOUD_TRAIL = "CLOUD_TRAIL"


class GuardDutyScanner(BaseScanner):
    """Scanner for AWS GuardDuty detector configurations.

    GuardDuty is a managed threat detection service. This scanner discovers:
    - Active GuardDuty detectors
    - Configured protection plans and their finding types

    Note: GuardDuty findings are vendor-managed detections with implicit
    MITRE mappings, so we catalog them rather than parse patterns.

    Protection plans detected:
    - Core (EC2/IAM) - always enabled with detector
    - S3 Protection - S3_DATA_EVENTS feature
    - EKS Protection - EKS_AUDIT_LOGS feature
    - RDS Protection - RDS_LOGIN_EVENTS feature
    - Lambda Protection - LAMBDA_NETWORK_LOGS feature
    - Malware Protection - EBS_MALWARE_PROTECTION feature
    - Runtime Monitoring - RUNTIME_MONITORING feature
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GUARDDUTY_FINDING

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan all regions for GuardDuty detectors in parallel."""
        return await self.scan_regions_parallel(regions, options)

    async def scan_region(
        self,
        region: str,
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan a single region for GuardDuty detectors and finding types."""
        detections = []
        client = self.session.client("guardduty", region_name=region)

        try:
            # List all detectors (non-blocking)
            paginator = client.get_paginator("list_detectors")
            detector_ids = []

            for page in await self.run_sync(lambda: list(paginator.paginate())):
                detector_ids.extend(page.get("DetectorIds", []))

            # Get details for each detector
            for detector_id in detector_ids:
                detector_detections = await self._scan_detector(
                    client, detector_id, region
                )
                detections.extend(detector_detections)

        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                self.logger.warning("guardduty_access_denied", region=region)
            else:
                raise

        return detections

    async def _scan_detector(
        self,
        client: Any,
        detector_id: str,
        region: str,
    ) -> list[RawDetection]:
        """Get detection configurations for a GuardDuty detector."""
        detections = []

        try:
            # Get detector details (non-blocking)
            detector = await self.run_sync(client.get_detector, DetectorId=detector_id)

            # Get configured features
            features = detector.get("Features", [])
            data_sources = detector.get("DataSources", {})

            # GuardDuty finding types that map to MITRE techniques
            # We create a detection for each enabled feature/finding category
            finding_categories = self._get_finding_categories(
                detector, features, data_sources
            )

            for category in finding_categories:
                detection = RawDetection(
                    name=f"GuardDuty-{category['name']}",
                    detection_type=DetectionType.GUARDDUTY_FINDING,
                    source_arn=f"arn:aws:guardduty:{region}:{await self._get_account_id()}:detector/{detector_id}",
                    region=region,
                    raw_config={
                        "detector_id": detector_id,
                        "detector_status": detector.get("Status"),
                        "category": category["name"],
                        "finding_types": category["finding_types"],
                        "features": features,
                        "data_sources": data_sources,
                    },
                    description=category["description"],
                    is_managed=False,  # Only DO-NOT-DELETE- EventBridge rules show badge
                )
                detections.append(detection)

        except ClientError as e:
            self.logger.warning(
                "guardduty_detector_error", detector_id=detector_id, error=str(e)
            )

        return detections

    async def _get_account_id(self) -> str:
        """Get AWS account ID from STS."""
        try:
            sts = self.session.client("sts")
            identity = await self.run_sync(sts.get_caller_identity)
            return identity["Account"]
        except Exception:
            return "unknown"

    def _is_feature_enabled(
        self,
        feature_name: str,
        features: list,
        data_sources: dict,
    ) -> bool:
        """Check if a GuardDuty feature is enabled.

        Checks both the 'features' array (new API) and 'dataSources' object
        (legacy API) for backwards compatibility.

        Args:
            feature_name: The feature name constant (e.g., S3_DATA_EVENTS)
            features: The features array from GetDetector response
            data_sources: The dataSources object from GetDetector response

        Returns:
            True if the feature is enabled via either API format.
        """
        # Check features array (new API format)
        for feature in features:
            if feature.get("Name") == feature_name:
                if feature.get("Status") == "ENABLED":
                    return True

        # Check dataSources (legacy API format)
        ds_mappings = {
            FEATURE_S3_DATA_EVENTS: lambda ds: (
                ds.get("S3Logs", {}).get("Status") == "ENABLED"
            ),
            FEATURE_EKS_AUDIT_LOGS: lambda ds: (
                ds.get("Kubernetes", {}).get("AuditLogs", {}).get("Status") == "ENABLED"
            ),
            FEATURE_EBS_MALWARE_PROTECTION: lambda ds: (
                ds.get("MalwareProtection", {})
                .get("ScanEc2InstanceWithFindings", {})
                .get("EbsVolumes", {})
                .get("Status")
                == "ENABLED"
            ),
        }

        if feature_name in ds_mappings:
            return ds_mappings[feature_name](data_sources)

        return False

    def _get_finding_categories(
        self,
        detector: dict,
        features: list,
        data_sources: dict,
    ) -> list[dict]:
        """Map GuardDuty capabilities to detection categories.

        Each category represents a class of threats GuardDuty detects.
        Checks both 'features' and 'dataSources' for backwards compatibility.
        """
        categories = []

        # Log detected features for debugging
        feature_status = {f.get("Name"): f.get("Status") for f in features}
        self.logger.debug(
            "guardduty_features_detected",
            features=feature_status,
            data_sources_keys=list(data_sources.keys()),
        )

        # Core threat detection (always enabled when detector is active)
        if detector.get("Status") == "ENABLED":
            categories.append(
                {
                    "name": "Reconnaissance",
                    "description": "Detects reconnaissance activities like port scans and API enumeration",
                    "finding_types": [
                        "Recon:EC2/PortProbeUnprotectedPort",
                        "Recon:EC2/PortProbeEMRUnprotectedPort",
                        "Recon:EC2/Portscan",
                        "Recon:IAMUser/MaliciousIPCaller",
                        "Recon:IAMUser/MaliciousIPCaller.Custom",
                        "Recon:IAMUser/TorIPCaller",
                    ],
                }
            )

            categories.append(
                {
                    "name": "UnauthorizedAccess",
                    "description": "Detects unauthorized access attempts and suspicious API activity",
                    "finding_types": [
                        "UnauthorizedAccess:EC2/SSHBruteForce",
                        "UnauthorizedAccess:EC2/RDPBruteForce",
                        "UnauthorizedAccess:EC2/TorClient",
                        "UnauthorizedAccess:EC2/TorRelay",
                        "UnauthorizedAccess:EC2/MetadataDNSRebind",
                        "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
                        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
                        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                        "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
                        "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
                        "UnauthorizedAccess:IAMUser/TorIPCaller",
                    ],
                }
            )

            categories.append(
                {
                    "name": "Persistence",
                    "description": "Detects attempts to establish persistence in the environment",
                    "finding_types": [
                        "Persistence:IAMUser/AnomalousBehavior",
                    ],
                }
            )

            categories.append(
                {
                    "name": "PrivilegeEscalation",
                    "description": "Detects privilege escalation attempts",
                    "finding_types": [
                        "PrivilegeEscalation:IAMUser/AnomalousBehavior",
                    ],
                }
            )

            categories.append(
                {
                    "name": "DefenseEvasion",
                    "description": "Detects attempts to evade security controls",
                    "finding_types": [
                        "DefenseEvasion:EC2/UnusualDNSResolver",
                        "DefenseEvasion:EC2/UnusualDoHActivity",
                        "DefenseEvasion:EC2/UnusualDoTActivity",
                        "DefenseEvasion:IAMUser/AnomalousBehavior",
                        "Stealth:IAMUser/CloudTrailLoggingDisabled",
                        "Stealth:IAMUser/PasswordPolicyChange",
                    ],
                }
            )

            categories.append(
                {
                    "name": "CredentialAccess",
                    "description": "Detects credential theft and abuse",
                    "finding_types": [
                        "CredentialAccess:IAMUser/AnomalousBehavior",
                    ],
                }
            )

            categories.append(
                {
                    "name": "Discovery",
                    "description": "Detects discovery and enumeration activity",
                    "finding_types": [
                        "Discovery:IAMUser/AnomalousBehavior",
                    ],
                }
            )

            categories.append(
                {
                    "name": "Exfiltration",
                    "description": "Detects data exfiltration attempts",
                    "finding_types": [
                        "Exfiltration:IAMUser/AnomalousBehavior",
                    ],
                }
            )

            categories.append(
                {
                    "name": "CryptoMining",
                    "description": "Detects cryptocurrency mining activity",
                    "finding_types": [
                        "CryptoCurrency:EC2/BitcoinTool.B",
                        "CryptoCurrency:EC2/BitcoinTool.B!DNS",
                    ],
                }
            )

            categories.append(
                {
                    "name": "Backdoor",
                    "description": "Detects backdoor activity and C2 communications",
                    "finding_types": [
                        "Backdoor:EC2/C&CActivity.B",
                        "Backdoor:EC2/C&CActivity.B!DNS",
                        "Backdoor:EC2/DenialOfService.Dns",
                        "Backdoor:EC2/DenialOfService.Tcp",
                        "Backdoor:EC2/DenialOfService.Udp",
                        "Backdoor:EC2/DenialOfService.UdpOnTcpPorts",
                        "Backdoor:EC2/DenialOfService.UnusualProtocol",
                        "Backdoor:EC2/Spambot",
                    ],
                }
            )

            categories.append(
                {
                    "name": "Trojan",
                    "description": "Detects trojan activity",
                    "finding_types": [
                        "Trojan:EC2/BlackholeTraffic",
                        "Trojan:EC2/BlackholeTraffic!DNS",
                        "Trojan:EC2/DGADomainRequest.B",
                        "Trojan:EC2/DGADomainRequest.C!DNS",
                        "Trojan:EC2/DNSDataExfiltration",
                        "Trojan:EC2/DriveBySourceTraffic!DNS",
                        "Trojan:EC2/DropPoint",
                        "Trojan:EC2/DropPoint!DNS",
                        "Trojan:EC2/PhishingDomainRequest!DNS",
                    ],
                }
            )

            categories.append(
                {
                    "name": "Impact",
                    "description": "Detects impact activities like data destruction",
                    "finding_types": [
                        "Impact:EC2/AbusedDomainRequest.Reputation",
                        "Impact:EC2/BitcoinDomainRequest.Reputation",
                        "Impact:EC2/MaliciousDomainRequest.Reputation",
                        "Impact:EC2/MaliciousDomainRequest.Custom",
                        "Impact:EC2/PortSweep",
                        "Impact:EC2/SuspiciousDomainRequest.Reputation",
                        "Impact:EC2/WinRMBruteForce",
                        "Impact:IAMUser/AnomalousBehavior",
                    ],
                }
            )

            categories.append(
                {
                    "name": "PenTest",
                    "description": "Detects penetration testing tool usage",
                    "finding_types": [
                        "PenTest:IAMUser/KaliLinux",
                        "PenTest:IAMUser/ParrotLinux",
                        "PenTest:IAMUser/PentooLinux",
                    ],
                }
            )

            categories.append(
                {
                    "name": "Policy",
                    "description": "Detects risky policy configurations",
                    "finding_types": [
                        "Policy:IAMUser/RootCredentialUsage",
                        "Policy:IAMUser/ShortTermRootCredentialUsage",
                    ],
                }
            )

        # S3 Protection (check both features and dataSources)
        if self._is_feature_enabled(FEATURE_S3_DATA_EVENTS, features, data_sources):
            categories.append(
                {
                    "name": "S3-DataProtection",
                    "description": "Detects suspicious S3 bucket access and data exfiltration",
                    "finding_types": [
                        "Discovery:S3/AnomalousBehavior",
                        "Discovery:S3/MaliciousIPCaller",
                        "Discovery:S3/MaliciousIPCaller.Custom",
                        "Discovery:S3/TorIPCaller",
                        "Exfiltration:S3/AnomalousBehavior",
                        "Exfiltration:S3/MaliciousIPCaller",
                        "Impact:S3/AnomalousBehavior.Delete",
                        "Impact:S3/AnomalousBehavior.Permission",
                        "Impact:S3/AnomalousBehavior.Write",
                        "Impact:S3/MaliciousIPCaller",
                        "Object:S3/MaliciousFile",
                        "PenTest:S3/KaliLinux",
                        "PenTest:S3/ParrotLinux",
                        "PenTest:S3/PentooLinux",
                        "Policy:S3/AccountBlockPublicAccessDisabled",
                        "Policy:S3/BucketBlockPublicAccessDisabled",
                        "Policy:S3/BucketAnonymousAccessGranted",
                        "Policy:S3/BucketPublicAccessGranted",
                        "Stealth:S3/ServerAccessLoggingDisabled",
                        "UnauthorizedAccess:S3/MaliciousIPCaller.Custom",
                        "UnauthorizedAccess:S3/TorIPCaller",
                    ],
                }
            )

        # EKS Protection (check both features and dataSources)
        if self._is_feature_enabled(FEATURE_EKS_AUDIT_LOGS, features, data_sources):
            categories.append(
                {
                    "name": "EKS-ThreatDetection",
                    "description": "Detects threats in EKS clusters via audit logs",
                    "finding_types": [
                        "CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed",
                        "CredentialAccess:Kubernetes/MaliciousIPCaller",
                        "CredentialAccess:Kubernetes/MaliciousIPCaller.Custom",
                        "CredentialAccess:Kubernetes/SuccessfulAnonymousAccess",
                        "CredentialAccess:Kubernetes/TorIPCaller",
                        "DefenseEvasion:Kubernetes/MaliciousIPCaller",
                        "DefenseEvasion:Kubernetes/MaliciousIPCaller.Custom",
                        "DefenseEvasion:Kubernetes/SuccessfulAnonymousAccess",
                        "DefenseEvasion:Kubernetes/TorIPCaller",
                        "Discovery:Kubernetes/AnomalousBehavior.PermissionChecked",
                        "Discovery:Kubernetes/MaliciousIPCaller",
                        "Discovery:Kubernetes/MaliciousIPCaller.Custom",
                        "Discovery:Kubernetes/SuccessfulAnonymousAccess",
                        "Discovery:Kubernetes/TorIPCaller",
                        "Execution:Kubernetes/AnomalousBehavior.ExecInPod",
                        "Execution:Kubernetes/AnomalousBehavior.WorkloadDeployed",
                        "Execution:Kubernetes/ExecInKubeSystemPod",
                        "Impact:Kubernetes/MaliciousIPCaller",
                        "Impact:Kubernetes/MaliciousIPCaller.Custom",
                        "Impact:Kubernetes/SuccessfulAnonymousAccess",
                        "Impact:Kubernetes/TorIPCaller",
                        "Persistence:Kubernetes/AnomalousBehavior.WorkloadDeployed!ContainerWithSensitiveMount",
                        "Persistence:Kubernetes/ContainerWithSensitiveMount",
                        "Persistence:Kubernetes/MaliciousIPCaller",
                        "Persistence:Kubernetes/MaliciousIPCaller.Custom",
                        "Persistence:Kubernetes/SuccessfulAnonymousAccess",
                        "Persistence:Kubernetes/TorIPCaller",
                        "Policy:Kubernetes/AdminAccessToDefaultServiceAccount",
                        "Policy:Kubernetes/AnonymousAccessGranted",
                        "Policy:Kubernetes/ExposedDashboard",
                        "Policy:Kubernetes/KubeflowDashboardExposed",
                        "PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleBindingCreated",
                        "PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleCreated",
                        "PrivilegeEscalation:Kubernetes/AnomalousBehavior.WorkloadDeployed!PrivilegedContainer",
                        "PrivilegeEscalation:Kubernetes/PrivilegedContainer",
                    ],
                }
            )

        # RDS Protection
        if self._is_feature_enabled(FEATURE_RDS_LOGIN_EVENTS, features, data_sources):
            categories.append(
                {
                    "name": "RDS-Protection",
                    "description": "Detects suspicious database login activity",
                    "finding_types": [
                        "CredentialAccess:RDS/AnomalousBehavior.FailedLogin",
                        "CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce",
                        "CredentialAccess:RDS/AnomalousBehavior.SuccessfulLogin",
                        "CredentialAccess:RDS/MaliciousIPCaller.FailedLogin",
                        "CredentialAccess:RDS/MaliciousIPCaller.SuccessfulLogin",
                        "CredentialAccess:RDS/TorIPCaller.FailedLogin",
                        "CredentialAccess:RDS/TorIPCaller.SuccessfulLogin",
                        "Discovery:RDS/MaliciousIPCaller",
                        "Discovery:RDS/TorIPCaller",
                    ],
                }
            )

        # Lambda Protection
        if self._is_feature_enabled(
            FEATURE_LAMBDA_NETWORK_LOGS, features, data_sources
        ):
            categories.append(
                {
                    "name": "Lambda-Protection",
                    "description": "Detects suspicious Lambda function network activity",
                    "finding_types": [
                        "Backdoor:Lambda/C&CActivity.B",
                        "CryptoCurrency:Lambda/BitcoinTool.B",
                        "Trojan:Lambda/BlackholeTraffic",
                        "Trojan:Lambda/DropPoint",
                        "UnauthorizedAccess:Lambda/MaliciousIPCaller.Custom",
                        "UnauthorizedAccess:Lambda/TorClient",
                        "UnauthorizedAccess:Lambda/TorRelay",
                    ],
                }
            )

        # Malware Protection (check both features and dataSources)
        if self._is_feature_enabled(
            FEATURE_EBS_MALWARE_PROTECTION, features, data_sources
        ):
            categories.append(
                {
                    "name": "MalwareProtection",
                    "description": "Detects malware on EBS volumes and containers",
                    "finding_types": [
                        "Execution:EC2/MaliciousFile",
                        "Execution:EC2/MaliciousFile!AMI",
                        "Execution:EC2/MaliciousFile!Snapshot",
                        "Execution:EC2/MaliciousFile!RecoveryPoint",
                        "Execution:EC2/SuspiciousFile",
                        "Execution:ECS/MaliciousFile",
                        "Execution:ECS/SuspiciousFile",
                        "Execution:Kubernetes/MaliciousFile",
                        "Execution:Kubernetes/SuspiciousFile",
                        "Execution:Container/MaliciousFile",
                        "Execution:Container/SuspiciousFile",
                        "Execution:S3/MaliciousFile!RecoveryPoint",
                    ],
                }
            )

        # Runtime Monitoring (EC2, ECS, EKS)
        if self._is_feature_enabled(FEATURE_RUNTIME_MONITORING, features, data_sources):
            categories.append(
                {
                    "name": "RuntimeMonitoring",
                    "description": "Detects runtime threats in EC2, ECS, and EKS workloads",
                    "finding_types": [
                        # Backdoor
                        "Backdoor:Runtime/C&CActivity.B",
                        "Backdoor:Runtime/C&CActivity.B!DNS",
                        # CryptoCurrency
                        "CryptoCurrency:Runtime/BitcoinTool.B",
                        "CryptoCurrency:Runtime/BitcoinTool.B!DNS",
                        # DefenseEvasion
                        "DefenseEvasion:Runtime/FilelessExecution",
                        "DefenseEvasion:Runtime/KernelModuleLoaded",
                        "DefenseEvasion:Runtime/ProcessInjection.Proc",
                        "DefenseEvasion:Runtime/ProcessInjection.Ptrace",
                        "DefenseEvasion:Runtime/ProcessInjection.VirtualMemoryWrite",
                        "DefenseEvasion:Runtime/PtraceAntiDebugging",
                        "DefenseEvasion:Runtime/SuspiciousCommand",
                        # Discovery
                        "Discovery:Runtime/SuspiciousCommand",
                        # Execution
                        "Execution:Runtime/MaliciousFileExecuted",
                        "Execution:Runtime/NewBinaryExecuted",
                        "Execution:Runtime/NewLibraryLoaded",
                        "Execution:Runtime/ReverseShell",
                        "Execution:Runtime/SuspiciousCommand",
                        "Execution:Runtime/SuspiciousShellCreated",
                        "Execution:Runtime/SuspiciousTool",
                        # Impact
                        "Impact:Runtime/AbusedDomainRequest.Reputation",
                        "Impact:Runtime/BitcoinDomainRequest.Reputation",
                        "Impact:Runtime/CryptoMinerExecuted",
                        "Impact:Runtime/MaliciousDomainRequest.Reputation",
                        "Impact:Runtime/SuspiciousDomainRequest.Reputation",
                        # Persistence
                        "Persistence:Runtime/SuspiciousCommand",
                        # PrivilegeEscalation
                        "PrivilegeEscalation:Runtime/CGroupsReleaseAgentModified",
                        "PrivilegeEscalation:Runtime/ContainerMountsHostDirectory",
                        "PrivilegeEscalation:Runtime/DockerSocketAccessed",
                        "PrivilegeEscalation:Runtime/ElevationToRoot",
                        "PrivilegeEscalation:Runtime/RuncContainerEscape",
                        "PrivilegeEscalation:Runtime/SuspiciousCommand",
                        "PrivilegeEscalation:Runtime/UserfaultfdUsage",
                        # Trojan
                        "Trojan:Runtime/BlackholeTraffic",
                        "Trojan:Runtime/BlackholeTraffic!DNS",
                        "Trojan:Runtime/DGADomainRequest.C!DNS",
                        "Trojan:Runtime/DriveBySourceTraffic!DNS",
                        "Trojan:Runtime/DropPoint",
                        "Trojan:Runtime/DropPoint!DNS",
                        "Trojan:Runtime/PhishingDomainRequest!DNS",
                        # UnauthorizedAccess
                        "UnauthorizedAccess:Runtime/MetadataDNSRebind",
                        "UnauthorizedAccess:Runtime/TorClient",
                        "UnauthorizedAccess:Runtime/TorRelay",
                    ],
                }
            )

        return categories
