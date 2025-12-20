"""GCP Security Command Center Findings Scanner.

Scans for active SCC findings to assess detection effectiveness.
This complements the configuration scanners by showing what's
actually being detected in the environment.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection


# SCC finding categories mapped to MITRE ATT&CK techniques
SCC_FINDING_MITRE_MAPPING = {
    # Event Threat Detection findings
    "ADDED_BINARY_EXECUTED": ["T1059"],
    "ADDED_LIBRARY_LOADED": ["T1055"],
    "ADDED_MALICIOUS_LIBRARY_LOADED": ["T1055"],
    "DEFENSE_EVASION_OBSERVED": ["T1562", "T1070"],
    "MALICIOUS_SCRIPT_EXECUTED": ["T1059"],
    "MALICIOUS_URL_OBSERVED": ["T1071"],
    "MODIFIED_BINARY_EXECUTED": ["T1036"],
    "REVERSE_SHELL": ["T1059"],
    "SSH_BRUTEFORCE": ["T1110"],
    "SSH_SUSPICIOUS_ACTIVITY": ["T1021.004"],
    "UNEXPECTED_CHILD_SHELL": ["T1059"],
    # Container Threat Detection
    "CONTAINER_BREAKOUT": ["T1611"],
    "CONTAINER_DRIFT": ["T1610"],
    "MALICIOUS_CONTAINER_IMAGE": ["T1204.003"],
    "PRIVILEGE_ESCALATION": ["T1068"],
    # VM Threat Detection
    "MALWARE_DETECTED": ["T1204"],
    "CRYPTOMINING_ACTIVITY": ["T1496"],
    "SUSPICIOUS_NETWORK_ACTIVITY": ["T1071"],
    # Sensitive Actions
    "IMPERSONATION": ["T1134"],
    "SERVICE_ACCOUNT_KEY_CREATION": ["T1528"],
    "IAM_POLICY_CHANGE": ["T1098"],
    "SENSITIVE_DATA_ACCESS": ["T1530"],
    # Web Security Scanner
    "XSS_CALLBACK": ["T1059.007"],
    "XSS_ERROR": ["T1059.007"],
    "SQL_INJECTION": ["T1190"],
    "SERVER_SIDE_REQUEST_FORGERY": ["T1190"],
    "MIXED_CONTENT": ["T1557"],
    # Security Health Analytics
    "MFA_NOT_ENABLED": ["T1078"],
    "PUBLIC_IP_ADDRESS": ["T1133"],
    "OPEN_FIREWALL": ["T1190"],
    "PUBLIC_BUCKET": ["T1530"],
    "PUBLIC_DATASET": ["T1530"],
    "WEAK_SSL_POLICY": ["T1557"],
    "DEFAULT_SERVICE_ACCOUNT": ["T1078.004"],
    "SERVICE_ACCOUNT_KEY_NOT_ROTATED": ["T1528"],
}


class SCCFindingsScanner(BaseScanner):
    """Scanner for SCC active findings.

    Retrieves security findings from Security Command Center
    to understand what threats are being detected.

    This helps assess the effectiveness of detection coverage
    by showing actual findings generated.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_SECURITY_COMMAND_CENTER

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan for SCC findings.

        Args:
            regions: Not used (SCC is global)
            options:
                - organization_id: GCP organisation ID (required)
                - lookback_days: Days to look back (default 7)
                - severity_filter: Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
                - state_filter: Finding state (ACTIVE, INACTIVE)
                - finding_classes: List of finding classes to retrieve

        Returns:
            List of RawDetection summarising active findings
        """
        detections = []
        options = options or {}
        org_id = options.get("organization_id")
        lookback_days = options.get("lookback_days", 7)
        severity_filter = options.get("severity_filter", "MEDIUM")
        state_filter = options.get("state_filter", "ACTIVE")
        finding_classes = options.get(
            "finding_classes",
            ["THREAT", "VULNERABILITY", "MISCONFIGURATION", "POSTURE_VIOLATION"],
        )

        if not org_id:
            self.logger.error("organization_id_required")
            return []

        try:
            from google.cloud import securitycenter_v1
            from google.api_core.exceptions import PermissionDenied

            client = securitycenter_v1.SecurityCenterClient(credentials=self.session)

            parent = f"organizations/{org_id}"

            # Calculate time filter
            lookback_time = datetime.now(timezone.utc) - timedelta(days=lookback_days)
            time_filter = lookback_time.isoformat()

            # Build filter string
            filter_parts = [
                f'state="{state_filter}"',
                f'event_time>="{time_filter}"',
            ]

            if severity_filter:
                severity_levels = self._get_severity_levels(severity_filter)
                if severity_levels:
                    severity_clause = " OR ".join(
                        f'severity="{s}"' for s in severity_levels
                    )
                    filter_parts.append(f"({severity_clause})")

            if finding_classes:
                class_clause = " OR ".join(
                    f'finding_class="{c}"' for c in finding_classes
                )
                filter_parts.append(f"({class_clause})")

            filter_string = " AND ".join(filter_parts)

            # Aggregate findings by category
            finding_counts: dict[str, dict[str, Any]] = {}

            request = {
                "parent": f"{parent}/sources/-",  # All sources
                "filter": filter_string,
                "order_by": "event_time desc",
            }

            for finding in client.list_findings(request=request):
                finding_data = finding.finding
                category = finding_data.category

                if category not in finding_counts:
                    finding_counts[category] = {
                        "count": 0,
                        "severities": {},
                        "sources": set(),
                        "latest_time": None,
                        "mitre_techniques": SCC_FINDING_MITRE_MAPPING.get(category, []),
                        "sample_resource": None,
                    }

                finding_counts[category]["count"] += 1
                severity = str(finding_data.severity).split(".")[-1]
                finding_counts[category]["severities"][severity] = (
                    finding_counts[category]["severities"].get(severity, 0) + 1
                )

                # Extract source
                source_name = finding_data.name.split("/findings/")[0].split("/")[-1]
                finding_counts[category]["sources"].add(source_name)

                # Track latest time
                if finding_data.event_time:
                    event_time = finding_data.event_time
                    if finding_counts[category]["latest_time"] is None:
                        finding_counts[category]["latest_time"] = event_time
                    elif event_time > finding_counts[category]["latest_time"]:
                        finding_counts[category]["latest_time"] = event_time

                # Store sample resource if first
                if not finding_counts[category]["sample_resource"]:
                    finding_counts[category][
                        "sample_resource"
                    ] = finding_data.resource_name

            # Create detections for each category
            for category, data in finding_counts.items():
                detection = self._create_finding_detection(
                    category=category,
                    data=data,
                    org_id=org_id,
                    lookback_days=lookback_days,
                )
                if detection:
                    detections.append(detection)

            self.logger.info(
                "scc_findings_scan_complete",
                org_id=org_id,
                categories_found=len(finding_counts),
                total_findings=sum(d["count"] for d in finding_counts.values()),
            )

        except PermissionDenied as e:
            self.logger.warning(
                "permission_denied_scc_findings",
                org_id=org_id,
                error=str(e),
            )
        except Exception as e:
            self.logger.error(
                "scc_findings_scan_failed",
                org_id=org_id,
                error=str(e),
            )

        return detections

    def _get_severity_levels(self, min_severity: str) -> list[str]:
        """Get severity levels at or above minimum."""
        levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        try:
            min_index = levels.index(min_severity.upper())
            return levels[min_index:]
        except ValueError:
            return levels

    def _create_finding_detection(
        self,
        category: str,
        data: dict[str, Any],
        org_id: str,
        lookback_days: int,
    ) -> Optional[RawDetection]:
        """Create a RawDetection from aggregated findings."""
        count = data["count"]
        severities = data["severities"]
        sources = list(data["sources"])
        latest_time = data["latest_time"]
        mitre_techniques = data["mitre_techniques"]

        # Determine highest severity
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev in severities:
                highest_severity = sev
                break
        else:
            highest_severity = "UNKNOWN"

        description = (
            f"SCC Finding: {category} - {count} finding(s) "
            f"in last {lookback_days} days (highest: {highest_severity})"
        )

        return RawDetection(
            name=f"SCC Finding: {category}",
            detection_type=self.detection_type,
            source_arn=f"scc/{org_id}/findings/{category}",
            region="global",
            raw_config={
                "category": category,
                "finding_count": count,
                "severities": severities,
                "highest_severity": highest_severity,
                "sources": sources,
                "latest_time": (
                    latest_time.isoformat()
                    if latest_time and hasattr(latest_time, "isoformat")
                    else str(latest_time) if latest_time else None
                ),
                "lookback_days": lookback_days,
                "sample_resource": data.get("sample_resource"),
                "mitre_techniques": mitre_techniques,
                "org_id": org_id,
            },
            description=description,
            is_managed=True,  # SCC is a managed service
        )


class SCCModuleStatusScanner(BaseScanner):
    """Scanner for SCC module enablement status.

    Checks which SCC modules (SHA, ETD, CTD, VMTD) are enabled
    to understand detection coverage capabilities.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_SECURITY_COMMAND_CENTER

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan for SCC module enablement status.

        Args:
            regions: Not used
            options:
                - organization_id: GCP organisation ID (required)

        Returns:
            List of RawDetection for enabled SCC modules
        """
        detections = []
        options = options or {}
        org_id = options.get("organization_id")

        if not org_id:
            self.logger.error("organization_id_required")
            return []

        try:
            from google.cloud import securitycenter_v1
            from google.api_core.exceptions import PermissionDenied

            client = securitycenter_v1.SecurityCenterClient(credentials=self.session)

            # Get organisation settings to check SCC tier
            org_settings_name = f"organizations/{org_id}/organizationSettings"

            try:
                org_settings = client.get_organization_settings(
                    request={"name": org_settings_name}
                )
                is_enabled = org_settings.enable_asset_discovery
            except Exception:
                is_enabled = None

            # Check for enabled modules by looking at sources
            parent = f"organizations/{org_id}"
            request = {"parent": parent}

            enabled_modules = []
            module_details: dict[str, dict] = {}

            for source in client.list_sources(request=request):
                display_name = source.display_name or ""
                source_name = source.name

                module_info = self._identify_module(display_name)
                if module_info:
                    module_name = module_info["name"]
                    if module_name not in module_details:
                        enabled_modules.append(module_name)
                        module_details[module_name] = {
                            "source_name": source_name,
                            "display_name": display_name,
                            "description": module_info["description"],
                            "mitre_coverage": module_info["mitre_techniques"],
                            "tier_required": module_info.get("tier", "standard"),
                        }

            # Create detections for enabled modules
            for module_name, details in module_details.items():
                detection = self._create_module_detection(
                    module_name=module_name,
                    details=details,
                    org_id=org_id,
                )
                if detection:
                    detections.append(detection)

            # Create summary detection
            summary_detection = self._create_summary_detection(
                enabled_modules=enabled_modules,
                is_enabled=is_enabled,
                org_id=org_id,
            )
            if summary_detection:
                detections.append(summary_detection)

            self.logger.info(
                "scc_module_status_scan_complete",
                org_id=org_id,
                enabled_modules=enabled_modules,
            )

        except PermissionDenied as e:
            self.logger.warning(
                "permission_denied_scc_modules",
                org_id=org_id,
                error=str(e),
            )
        except Exception as e:
            self.logger.error(
                "scc_module_status_scan_failed",
                org_id=org_id,
                error=str(e),
            )

        return detections

    def _identify_module(self, display_name: str) -> Optional[dict]:
        """Identify SCC module from source display name."""
        display_lower = display_name.lower()

        modules = {
            "security health analytics": {
                "name": "Security Health Analytics",
                "description": "Detects misconfigurations and compliance issues",
                "mitre_techniques": ["T1078", "T1530", "T1190", "T1133"],
                "tier": "standard",
            },
            "event threat detection": {
                "name": "Event Threat Detection",
                "description": "Detects threats from Cloud Audit Logs",
                "mitre_techniques": [
                    "T1098",
                    "T1134",
                    "T1528",
                    "T1562",
                    "T1110",
                    "T1021",
                ],
                "tier": "premium",
            },
            "container threat detection": {
                "name": "Container Threat Detection",
                "description": "Detects container runtime threats",
                "mitre_techniques": ["T1611", "T1610", "T1059", "T1068"],
                "tier": "premium",
            },
            "virtual machine threat detection": {
                "name": "VM Threat Detection",
                "description": "Detects cryptomining and malware on VMs",
                "mitre_techniques": ["T1496", "T1204", "T1071"],
                "tier": "premium",
            },
            "web security scanner": {
                "name": "Web Security Scanner",
                "description": "Scans web apps for vulnerabilities",
                "mitre_techniques": ["T1190", "T1059.007", "T1557"],
                "tier": "premium",
            },
        }

        for key, info in modules.items():
            if key in display_lower:
                return info

        return None

    def _create_module_detection(
        self,
        module_name: str,
        details: dict,
        org_id: str,
    ) -> Optional[RawDetection]:
        """Create a RawDetection for an enabled SCC module."""
        return RawDetection(
            name=f"SCC Module: {module_name}",
            detection_type=self.detection_type,
            source_arn=details["source_name"],
            region="global",
            raw_config={
                "module_name": module_name,
                "source_name": details["source_name"],
                "display_name": details["display_name"],
                "tier_required": details["tier_required"],
                "mitre_coverage": details["mitre_coverage"],
                "org_id": org_id,
            },
            description=details["description"],
            is_managed=True,
        )

    def _create_summary_detection(
        self,
        enabled_modules: list[str],
        is_enabled: Optional[bool],
        org_id: str,
    ) -> Optional[RawDetection]:
        """Create a summary detection for SCC status."""
        premium_modules = [
            "Event Threat Detection",
            "Container Threat Detection",
            "VM Threat Detection",
            "Web Security Scanner",
        ]

        has_premium = any(m in enabled_modules for m in premium_modules)
        tier = "Premium" if has_premium else "Standard"

        return RawDetection(
            name=f"SCC Status: {tier} Tier",
            detection_type=self.detection_type,
            source_arn=f"scc/{org_id}/status",
            region="global",
            raw_config={
                "tier": tier,
                "enabled_modules": enabled_modules,
                "module_count": len(enabled_modules),
                "asset_discovery_enabled": is_enabled,
                "org_id": org_id,
            },
            description=f"Security Command Center {tier} with {len(enabled_modules)} modules",
            is_managed=True,
        )
