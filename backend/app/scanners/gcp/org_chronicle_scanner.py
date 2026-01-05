"""GCP Chronicle/SecOps Organisation Scanner.

Scans for Chronicle SIEM configurations at the organisation level including:
- Detection rules (YARA-L 2.0 rules)
- Reference lists (whitelists/blacklists)
- Data tables
- Parsers

Based on the official secops Python SDK:
https://pypi.org/project/secops/
https://github.com/google/secops-wrapper
"""

from typing import TYPE_CHECKING, Any, Optional

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection

if TYPE_CHECKING:
    from secops import SecOpsClient


class OrgChronicleScanner(BaseScanner):
    """Scanner for organisation-level Chronicle/SecOps configurations.

    Chronicle (Google SecOps) provides:
    - Detection rules written in YARA-L 2.0
    - Reference lists for IOC management
    - Data tables for contextual enrichment
    - Log parsers for normalisation

    This scanner discovers detection coverage from Chronicle.

    Requires the secops SDK: pip install secops
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_CHRONICLE

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan for Chronicle detection rules and configurations.

        Args:
            regions: Not used (Chronicle is global)
            options: Configuration including:
                - customer_id: Chronicle instance ID
                - project_id: GCP project ID linked to Chronicle
                - region: Chronicle region (us, europe, asia-southeast1)
                - organization_id: GCP organisation ID (for context)

        Returns:
            List of RawDetection for Chronicle configurations
        """
        detections = []
        options = options or {}
        customer_id = options.get("customer_id")
        project_id = options.get("project_id")
        region = options.get("region", "us")
        org_id = options.get("organization_id")

        if not customer_id or not project_id:
            self.logger.error("customer_id_and_project_id_required_for_chronicle")
            return []

        try:
            from secops import SecOpsClient

            # Initialise SecOps client
            # The SDK uses the credentials from the session/environment
            client = SecOpsClient()

            # Create Chronicle-specific client
            chronicle = client.chronicle(
                customer_id=customer_id,
                project_id=project_id,
                region=region,
            )

            # Scan detection rules
            rule_detections = await self._scan_detection_rules(
                chronicle, org_id, customer_id
            )
            detections.extend(rule_detections)

            # Scan reference lists
            reference_detections = await self._scan_reference_lists(
                chronicle, org_id, customer_id
            )
            detections.extend(reference_detections)

            # Scan parsers
            parser_detections = await self._scan_parsers(chronicle, org_id, customer_id)
            detections.extend(parser_detections)

            self.logger.info(
                "chronicle_scan_complete",
                customer_id=customer_id,
                rule_count=len(rule_detections),
                reference_count=len(reference_detections),
                parser_count=len(parser_detections),
            )

        except ImportError:
            self.logger.warning(
                "secops_sdk_not_installed",
                message="Install with: pip install secops",
            )
        except Exception as e:
            error_str = str(e).lower()
            if "not found" in error_str or "not enabled" in error_str:
                self.logger.info(
                    "chronicle_not_enabled",
                    customer_id=customer_id,
                )
            elif "permission" in error_str or "unauthorized" in error_str:
                self.logger.warning(
                    "permission_denied_chronicle",
                    customer_id=customer_id,
                    error=str(e),
                )
            else:
                self.logger.error(
                    "chronicle_scan_failed",
                    customer_id=customer_id,
                    error=str(e),
                )

        return detections

    async def _scan_detection_rules(
        self, chronicle: "SecOpsClient", org_id: Optional[str], customer_id: str
    ) -> list[RawDetection]:
        """Scan for YARA-L 2.0 detection rules."""
        detections = []

        try:
            # List all detection rules
            # The SDK returns rule objects with properties like rule_id, rule_text, etc.
            rules = chronicle.list_rules()

            for rule in rules:
                detection = self._create_rule_detection(rule, org_id, customer_id)
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.warning(
                "scan_detection_rules_failed",
                error=str(e),
            )

        return detections

    def _create_rule_detection(
        self, rule: Any, org_id: Optional[str], customer_id: str
    ) -> Optional[RawDetection]:
        """Create a RawDetection from a Chronicle detection rule.

        Rule object properties from the SDK:
        - rule_id: Unique identifier
        - rule_text: YARA-L 2.0 rule content
        - display_name or name: Human-readable name
        - severity: Rule severity level
        - enabled: Whether rule is active
        """
        # Handle both object attributes and dict access
        rule_id = getattr(rule, "rule_id", None) or rule.get("ruleId", "")
        rule_text = getattr(rule, "rule_text", None) or rule.get("ruleText", "")
        display_name = (
            getattr(rule, "display_name", None)
            or getattr(rule, "name", None)
            or rule.get("displayName")
            or rule.get("name", rule_id)
        )
        severity = getattr(rule, "severity", None) or rule.get("severity", "UNKNOWN")
        enabled = getattr(rule, "enabled", None)
        if enabled is None:
            enabled = rule.get("enabled", True)

        # Extract MITRE ATT&CK technique IDs from rule text
        mitre_techniques = self._extract_mitre_from_rule(rule_text)

        description = f"Chronicle Rule: {display_name} (Severity: {severity})"

        return RawDetection(
            name=f"Chronicle Rule: {display_name}",
            detection_type=self.detection_type,
            source_arn=f"chronicle/{customer_id}/rules/{rule_id}",
            region="global",
            raw_config={
                "rule_id": rule_id,
                "display_name": display_name,
                "severity": severity,
                "enabled": enabled,
                "rule_text_preview": rule_text[:1000] if rule_text else None,
                "mitre_techniques": mitre_techniques,
                "org_id": org_id,
                "customer_id": customer_id,
            },
            query_pattern=rule_text,
            description=description,
            is_managed=False,
        )

    def _extract_mitre_from_rule(self, rule_text: str) -> list[str]:
        """Extract MITRE ATT&CK technique IDs from rule text.

        Chronicle YARA-L rules often include MITRE technique IDs in
        metadata sections or comments.
        """
        import re

        techniques = []

        if not rule_text:
            return techniques

        # Pattern for MITRE technique IDs: T1234 or T1234.001
        pattern = r"\bT\d{4}(?:\.\d{3})?\b"
        matches = re.findall(pattern, rule_text, re.IGNORECASE)
        techniques.extend(list(set(m.upper() for m in matches)))

        return techniques

    async def _scan_reference_lists(
        self, chronicle: "SecOpsClient", org_id: Optional[str], customer_id: str
    ) -> list[RawDetection]:
        """Scan for reference lists (IOC lists, allow/block lists)."""
        detections = []

        try:
            # List reference lists using the SDK
            ref_lists = chronicle.list_reference_lists()

            for ref_list in ref_lists:
                detection = self._create_reference_list_detection(
                    ref_list, org_id, customer_id
                )
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.warning(
                "scan_reference_lists_failed",
                error=str(e),
            )

        return detections

    def _create_reference_list_detection(
        self, ref_list: Any, org_id: Optional[str], customer_id: str
    ) -> Optional[RawDetection]:
        """Create a RawDetection from a reference list."""
        list_name = getattr(ref_list, "name", None) or ref_list.get("name", "")
        description = getattr(ref_list, "description", None) or ref_list.get(
            "description", ""
        )
        syntax_type = getattr(ref_list, "syntax_type", None) or ref_list.get(
            "syntaxType", "UNKNOWN"
        )

        # Entry count if available
        lines = getattr(ref_list, "lines", None) or ref_list.get("lines", [])
        entry_count = len(lines) if isinstance(lines, list) else 0

        return RawDetection(
            name=f"Chronicle Reference List: {list_name}",
            detection_type=self.detection_type,
            source_arn=f"chronicle/{customer_id}/reference_lists/{list_name}",
            region="global",
            raw_config={
                "name": list_name,
                "description": description,
                "syntax_type": syntax_type,
                "entry_count": entry_count,
                "org_id": org_id,
                "customer_id": customer_id,
            },
            description=f"Chronicle Reference List: {list_name} ({entry_count} entries)",
            is_managed=False,
        )

    async def _scan_parsers(
        self, chronicle: "SecOpsClient", org_id: Optional[str], customer_id: str
    ) -> list[RawDetection]:
        """Scan for log parsers.

        Parsers transform raw logs into normalised UDM format.
        Custom parsers indicate log sources being monitored.
        """
        detections = []

        try:
            # List parsers using the SDK
            parsers = chronicle.list_parsers()

            for parser in parsers:
                detection = self._create_parser_detection(parser, org_id, customer_id)
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.warning(
                "scan_parsers_failed",
                error=str(e),
            )

        return detections

    def _create_parser_detection(
        self, parser: Any, org_id: Optional[str], customer_id: str
    ) -> Optional[RawDetection]:
        """Create a RawDetection from a parser configuration."""
        parser_name = (
            getattr(parser, "log_type", None)
            or getattr(parser, "name", None)
            or parser.get("logType")
            or parser.get("name", "")
        )
        state = getattr(parser, "state", None) or parser.get("state", "UNKNOWN")
        parser_type = getattr(parser, "type", None) or parser.get("type", "CUSTOM")

        # Skip built-in parsers - focus on custom configurations
        if parser_type == "BUILTIN":
            return None

        return RawDetection(
            name=f"Chronicle Parser: {parser_name}",
            detection_type=self.detection_type,
            source_arn=f"chronicle/{customer_id}/parsers/{parser_name}",
            region="global",
            raw_config={
                "name": parser_name,
                "state": state,
                "parser_type": parser_type,
                "org_id": org_id,
                "customer_id": customer_id,
            },
            description=f"Chronicle Parser: {parser_name} ({state})",
            is_managed=False,  # Only DO-NOT-DELETE- EventBridge rules show badge
        )


class ChronicleRuleAlertsScanner(BaseScanner):
    """Scanner for Chronicle rule-generated alerts.

    Discovers which rules are actively generating alerts,
    indicating effective detection coverage.
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.GCP_CHRONICLE

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan for active rule alerts.

        Args:
            regions: Not used
            options: Must include customer_id, project_id, region

        Returns:
            List of RawDetection for rules with recent alerts
        """
        detections = []
        options = options or {}
        customer_id = options.get("customer_id")
        project_id = options.get("project_id")
        region = options.get("region", "us")
        org_id = options.get("organization_id")
        lookback_hours = options.get("lookback_hours", 24)

        if not customer_id or not project_id:
            self.logger.error("customer_id_and_project_id_required")
            return []

        try:
            from secops import SecOpsClient
            from datetime import datetime, timedelta

            client = SecOpsClient()
            chronicle = client.chronicle(
                customer_id=customer_id,
                project_id=project_id,
                region=region,
            )

            # Get rules with recent alerts
            # Use search_rule_alerts to find active rules
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=lookback_hours)

            # First, list all rules
            rules = chronicle.list_rules()

            for rule in rules:
                rule_id = getattr(rule, "rule_id", None) or rule.get("ruleId", "")

                try:
                    # Search for alerts from this rule
                    alerts = chronicle.search_rule_alerts(
                        rule_id=rule_id,
                        start_time=start_time,
                        end_time=end_time,
                    )

                    if alerts and len(alerts) > 0:
                        detection = self._create_active_rule_detection(
                            rule, len(alerts), org_id, customer_id
                        )
                        if detection:
                            detections.append(detection)

                except Exception:
                    # Rule may not have alerts or search failed
                    pass

            self.logger.info(
                "chronicle_alerts_scan_complete",
                active_rules=len(detections),
            )

        except ImportError:
            self.logger.warning("secops_sdk_not_installed")
        except Exception as e:
            self.logger.error(
                "chronicle_alerts_scan_failed",
                error=str(e),
            )

        return detections

    def _create_active_rule_detection(
        self, rule: Any, alert_count: int, org_id: Optional[str], customer_id: str
    ) -> Optional[RawDetection]:
        """Create a detection for an actively alerting rule."""
        rule_id = getattr(rule, "rule_id", None) or rule.get("ruleId", "")
        display_name = (
            getattr(rule, "display_name", None)
            or getattr(rule, "name", None)
            or rule.get("displayName")
            or rule.get("name", rule_id)
        )
        severity = getattr(rule, "severity", None) or rule.get("severity", "UNKNOWN")

        return RawDetection(
            name=f"Active Chronicle Rule: {display_name}",
            detection_type=self.detection_type,
            source_arn=f"chronicle/{customer_id}/rules/{rule_id}/active",
            region="global",
            raw_config={
                "rule_id": rule_id,
                "display_name": display_name,
                "severity": severity,
                "recent_alert_count": alert_count,
                "org_id": org_id,
                "customer_id": customer_id,
            },
            description=f"Active Rule: {display_name} ({alert_count} recent alerts)",
            is_managed=False,
        )
