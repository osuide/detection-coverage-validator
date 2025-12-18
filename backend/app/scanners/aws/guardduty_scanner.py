"""AWS GuardDuty scanner for managed threat detection findings."""

from typing import Any, Optional
from botocore.exceptions import ClientError

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


class GuardDutyScanner(BaseScanner):
    """Scanner for AWS GuardDuty detector configurations.

    GuardDuty is a managed threat detection service. This scanner discovers:
    - Active GuardDuty detectors
    - Configured finding types and their mappings

    Note: GuardDuty findings are vendor-managed detections with implicit
    MITRE mappings, so we catalog them rather than parse patterns.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GUARDDUTY_FINDING

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan all regions for GuardDuty detectors."""
        all_detections = []

        for region in regions:
            try:
                region_detections = await self.scan_region(region, options)
                all_detections.extend(region_detections)
            except ClientError as e:
                self.logger.warning(
                    "guardduty_scan_error",
                    region=region,
                    error=str(e)
                )

        return all_detections

    async def scan_region(
        self,
        region: str,
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan a single region for GuardDuty detectors and finding types."""
        detections = []
        client = self.session.client("guardduty", region_name=region)

        try:
            # List all detectors
            paginator = client.get_paginator("list_detectors")
            detector_ids = []

            for page in paginator.paginate():
                detector_ids.extend(page.get("DetectorIds", []))

            # Get details for each detector
            for detector_id in detector_ids:
                detector_detections = self._scan_detector(
                    client, detector_id, region
                )
                detections.extend(detector_detections)

        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                self.logger.warning("guardduty_access_denied", region=region)
            else:
                raise

        return detections

    def _scan_detector(
        self,
        client: Any,
        detector_id: str,
        region: str,
    ) -> list[RawDetection]:
        """Get detection configurations for a GuardDuty detector."""
        detections = []

        try:
            # Get detector details
            detector = client.get_detector(DetectorId=detector_id)

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
                    source_arn=f"arn:aws:guardduty:{region}:{self._get_account_id(client)}:detector/{detector_id}",
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
                    is_managed=True,  # GuardDuty is a managed service
                )
                detections.append(detection)

        except ClientError as e:
            self.logger.warning(
                "guardduty_detector_error",
                detector_id=detector_id,
                error=str(e)
            )

        return detections

    def _get_account_id(self, client: Any) -> str:
        """Get AWS account ID from STS."""
        try:
            sts = self.session.client("sts")
            return sts.get_caller_identity()["Account"]
        except Exception:
            return "unknown"

    def _get_finding_categories(
        self,
        detector: dict,
        features: list,
        data_sources: dict,
    ) -> list[dict]:
        """Map GuardDuty capabilities to detection categories.

        Each category represents a class of threats GuardDuty detects.
        """
        categories = []

        # Core threat detection (always enabled)
        if detector.get("Status") == "ENABLED":
            categories.append({
                "name": "Reconnaissance",
                "description": "Detects reconnaissance activities like port scans and API enumeration",
                "finding_types": [
                    "Recon:EC2/PortProbeUnprotectedPort",
                    "Recon:EC2/Portscan",
                    "Recon:IAMUser/NetworkPermissions",
                    "Recon:IAMUser/ResourcePermissions",
                    "Recon:IAMUser/UserPermissions",
                ]
            })

            categories.append({
                "name": "UnauthorizedAccess",
                "description": "Detects unauthorized access attempts and suspicious API activity",
                "finding_types": [
                    "UnauthorizedAccess:EC2/SSHBruteForce",
                    "UnauthorizedAccess:EC2/RDPBruteForce",
                    "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
                    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                    "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
                    "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
                    "UnauthorizedAccess:IAMUser/TorIPCaller",
                ]
            })

            categories.append({
                "name": "Persistence",
                "description": "Detects attempts to establish persistence in the environment",
                "finding_types": [
                    "Persistence:IAMUser/NetworkPermissions",
                    "Persistence:IAMUser/ResourcePermissions",
                    "Persistence:IAMUser/UserPermissions",
                ]
            })

            categories.append({
                "name": "PrivilegeEscalation",
                "description": "Detects privilege escalation attempts",
                "finding_types": [
                    "PrivilegeEscalation:IAMUser/AdministrativePermissions",
                ]
            })

            categories.append({
                "name": "DefenseEvasion",
                "description": "Detects attempts to evade security controls",
                "finding_types": [
                    "DefenseEvasion:EC2/UnusualDNSResolver",
                    "DefenseEvasion:EC2/UnusualDoHActivity",
                    "DefenseEvasion:EC2/UnusualDoTActivity",
                    "Stealth:IAMUser/CloudTrailLoggingDisabled",
                    "Stealth:IAMUser/PasswordPolicyChange",
                    "Stealth:IAMUser/LoggingConfigurationModified",
                ]
            })

            categories.append({
                "name": "CredentialAccess",
                "description": "Detects credential theft and abuse",
                "finding_types": [
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                    "CredentialAccess:Kubernetes/MaliciousIPCaller",
                    "CredentialAccess:Kubernetes/MaliciousIPCaller.Custom",
                    "CredentialAccess:Kubernetes/SuccessfulAnonymousAccess",
                ]
            })

            categories.append({
                "name": "CryptoMining",
                "description": "Detects cryptocurrency mining activity",
                "finding_types": [
                    "CryptoCurrency:EC2/BitcoinTool.B",
                    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
                    "CryptoCurrency:Runtime/BitcoinTool.B",
                    "CryptoCurrency:Runtime/BitcoinTool.B!DNS",
                ]
            })

            categories.append({
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
                ]
            })

            categories.append({
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
                ]
            })

            categories.append({
                "name": "Impact",
                "description": "Detects impact activities like data destruction",
                "finding_types": [
                    "Impact:EC2/AbusedDomainRequest.Reputation",
                    "Impact:EC2/BitcoinDomainRequest.Reputation",
                    "Impact:EC2/MaliciousDomainRequest.Reputation",
                    "Impact:EC2/PortSweep",
                    "Impact:EC2/SuspiciousDomainRequest.Reputation",
                    "Impact:EC2/WinRMBruteForce",
                ]
            })

        # S3 Protection
        s3_status = data_sources.get("S3Logs", {}).get("Status", "DISABLED")
        if s3_status == "ENABLED":
            categories.append({
                "name": "S3-DataProtection",
                "description": "Detects suspicious S3 bucket access and data exfiltration",
                "finding_types": [
                    "Exfiltration:S3/MaliciousIPCaller",
                    "Exfiltration:S3/ObjectRead.Unusual",
                    "Impact:S3/MaliciousIPCaller",
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
                ]
            })

        # EKS Protection
        eks_audit_logs = data_sources.get("Kubernetes", {}).get("AuditLogs", {}).get("Status", "DISABLED")
        if eks_audit_logs == "ENABLED":
            categories.append({
                "name": "EKS-ThreatDetection",
                "description": "Detects threats in EKS clusters",
                "finding_types": [
                    "CredentialAccess:Kubernetes/MaliciousIPCaller",
                    "Discovery:Kubernetes/MaliciousIPCaller",
                    "Execution:Kubernetes/ExecInKubeSystemPod",
                    "Impact:Kubernetes/MaliciousIPCaller",
                    "Persistence:Kubernetes/ContainerWithSensitiveMount",
                    "Persistence:Kubernetes/MaliciousIPCaller",
                    "PrivilegeEscalation:Kubernetes/PrivilegedContainer",
                    "Policy:Kubernetes/AdminAccessToDefaultServiceAccount",
                    "Policy:Kubernetes/AnonymousAccessGranted",
                    "Policy:Kubernetes/ExposedDashboard",
                    "Policy:Kubernetes/KubeflowDashboardExposed",
                ]
            })

        # Malware Protection
        malware_protection = next(
            (f for f in features if f.get("Name") == "EBS_MALWARE_PROTECTION"),
            {}
        )
        if malware_protection.get("Status") == "ENABLED":
            categories.append({
                "name": "MalwareProtection",
                "description": "Detects malware on EBS volumes",
                "finding_types": [
                    "Execution:EC2/MaliciousFile",
                    "Execution:ECS/MaliciousFile",
                    "Execution:Kubernetes/MaliciousFile",
                    "Execution:Container/MaliciousFile",
                    "Execution:EC2/SuspiciousFile",
                    "Execution:ECS/SuspiciousFile",
                    "Execution:Kubernetes/SuspiciousFile",
                    "Execution:Container/SuspiciousFile",
                ]
            })

        # Runtime Monitoring (Lambda, ECS, EKS)
        runtime_monitoring = next(
            (f for f in features if f.get("Name") == "RUNTIME_MONITORING"),
            {}
        )
        if runtime_monitoring.get("Status") == "ENABLED":
            categories.append({
                "name": "RuntimeMonitoring",
                "description": "Detects runtime threats in Lambda, ECS, and EKS",
                "finding_types": [
                    "Execution:Runtime/NewBinaryExecuted",
                    "Execution:Runtime/NewLibraryLoaded",
                    "Execution:Runtime/ReverseShell",
                    "Execution:Runtime/SuspiciousCommand",
                    "Execution:Runtime/SuspiciousFile",
                    "Execution:Runtime/SuspiciousTool",
                    "PrivilegeEscalation:Runtime/DockerSocketAccessed",
                    "PrivilegeEscalation:Runtime/RuncContainerEscape",
                    "PrivilegeEscalation:Runtime/CGroupsReleaseAgentModified",
                    "DefenseEvasion:Runtime/FilelessExecution",
                    "DefenseEvasion:Runtime/ProcessInjection.Ptrace",
                    "DefenseEvasion:Runtime/ProcessInjection.VirtualMemoryWrite",
                ]
            })

        return categories
