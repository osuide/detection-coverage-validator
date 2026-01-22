"""Azure Policy compliance scanner.

Discovers policy assignments and their compliance states from Azure Policy.
Unlike Defender, Policy does not include native MITRE tags - mappings are
pattern-based in azure_policy_mappings.py.
"""

from typing import Any, Optional

import structlog

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection

logger = structlog.get_logger()


class PolicyScanner(BaseScanner):
    """Scanner for Azure Policy compliance assessments.

    Azure Policy provides compliance assessments for governance and security.
    This scanner discovers policy assignments and their compliance states.

    Security Architecture:
    - Uses Azure Resource Manager API via azure.mgmt.policyinsights
    - Authenticated via Workload Identity Federation (no static credentials)
    - Scans subscription-level policy assignments and states
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.AZURE_POLICY

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan Azure subscription for Policy compliance assessments.

        Args:
            regions: Ignored - Policy is subscription-level, not regional
            options: Must contain subscription_id

        Returns:
            List of RawDetection objects (MITRE mappings via pattern mapper)

        Raises:
            ValueError: If subscription_id not provided
            Exception: For Azure API errors (logged and re-raised)
        """
        if not options or "subscription_id" not in options:
            raise ValueError("subscription_id required for Azure Policy scanning")

        subscription_id = options["subscription_id"]
        self.logger.info("scanning_policy", subscription_id=subscription_id)

        all_detections = []

        try:
            from azure.mgmt.policyinsights.aio import PolicyInsightsClient
            from azure.core.exceptions import (
                AzureError,
                HttpResponseError,
                ResourceNotFoundError,
            )

            # Create Policy Insights client with WIF credentials
            # self.session is async ClientAssertionCredential from azure_wif_service
            # CRITICAL: Must use async client from .aio module with async credential
            async with PolicyInsightsClient(
                credential=self.session, subscription_id=subscription_id
            ) as client:
                # Scan policy assignments and states
                assignments = await self._scan_policy_assignments(
                    client, subscription_id
                )
                all_detections.extend(assignments)

            self.logger.info(
                "policy_scan_complete",
                subscription_id=subscription_id,
                assignment_count=len(assignments),
            )

        except ResourceNotFoundError as e:
            # Policy not enabled or no assignments - log but don't raise
            self.logger.warning(
                "policy_not_enabled", subscription_id=subscription_id, error=str(e)
            )

        except HttpResponseError as e:
            # Permission denied or other HTTP error
            self.logger.error(
                "policy_http_error",
                subscription_id=subscription_id,
                status_code=e.status_code if hasattr(e, "status_code") else None,
                error=str(e),
            )
            raise

        except AzureError as e:
            # Other Azure SDK errors
            self.logger.error(
                "policy_azure_error", subscription_id=subscription_id, error=str(e)
            )
            raise

        except ImportError:
            self.logger.error("policy_client_not_installed")
            raise

        return all_detections

    async def _scan_policy_assignments(
        self, client: Any, subscription_id: str
    ) -> list[RawDetection]:
        """Scan for Policy assignments and their compliance states.

        Args:
            client: PolicyInsightsClient instance
            subscription_id: Azure subscription ID

        Returns:
            List of RawDetection objects for each policy assignment
        """
        detections = []

        try:
            # Query policy states at subscription scope
            # This gets the latest compliance state for all policy assignments
            # Use async iteration with the async Azure SDK client
            policy_states = []
            async for state in client.policy_states.list_query_results_for_subscription(
                policy_states_resource="latest",
                subscription_id=subscription_id,
            ):
                policy_states.append(state)

            # Group policy states by assignment for aggregation
            assignment_map: dict[str, list] = {}
            for state in policy_states:
                assignment_id = (
                    state.policy_assignment_id
                    if hasattr(state, "policy_assignment_id")
                    else None
                )
                if assignment_id:
                    if assignment_id not in assignment_map:
                        assignment_map[assignment_id] = []
                    assignment_map[assignment_id].append(state)

            # Create detection for each unique policy assignment
            for assignment_id, states in assignment_map.items():
                detection = self._parse_policy_assignment(
                    assignment_id, states, subscription_id
                )
                if detection:
                    detections.append(detection)

        except Exception as e:
            self.logger.error(
                "policy_states_scan_error",
                subscription_id=subscription_id,
                error=str(e),
            )
            raise

        return detections

    def _parse_policy_assignment(
        self, assignment_id: str, states: list, subscription_id: str
    ) -> Optional[RawDetection]:
        """Parse policy assignment and compliance states into RawDetection.

        Args:
            assignment_id: Policy assignment ID
            states: List of PolicyState objects for this assignment
            subscription_id: Azure subscription ID

        Returns:
            RawDetection with aggregated compliance data
        """
        try:
            # Extract assignment details from first state (all share same assignment)
            first_state = states[0]

            assignment_name = (
                first_state.policy_assignment_name
                if hasattr(first_state, "policy_assignment_name")
                else assignment_id.split("/")[-1]
            )

            policy_definition_id = (
                first_state.policy_definition_id
                if hasattr(first_state, "policy_definition_id")
                else None
            )

            # Aggregate compliance results
            compliant_count = sum(
                1
                for s in states
                if hasattr(s, "compliance_state") and s.compliance_state == "Compliant"
            )
            non_compliant_count = sum(
                1
                for s in states
                if hasattr(s, "compliance_state")
                and s.compliance_state == "NonCompliant"
            )

            # Build raw_config with assignment and compliance data
            raw_config = {
                "assignmentId": assignment_id,
                "assignmentName": assignment_name,
                "policyDefinitionId": policy_definition_id,
                "subscriptionId": subscription_id,
                "compliance": {
                    "compliant": compliant_count,
                    "nonCompliant": non_compliant_count,
                    "total": len(states),
                },
                "states": [
                    {
                        "resourceId": (
                            s.resource_id if hasattr(s, "resource_id") else None
                        ),
                        "complianceState": (
                            s.compliance_state
                            if hasattr(s, "compliance_state")
                            else "Unknown"
                        ),
                        "policyDefinitionAction": (
                            s.policy_definition_action
                            if hasattr(s, "policy_definition_action")
                            else None
                        ),
                    }
                    for s in states[:100]  # Limit to first 100 states for size
                ],
            }

            description = f"Policy assignment: {assignment_name} ({non_compliant_count} non-compliant)"

            return RawDetection(
                name=assignment_name,
                detection_type=DetectionType.AZURE_POLICY,
                source_arn=assignment_id,
                region="global",  # Policy is subscription-level
                raw_config=raw_config,
                description=description,
                is_managed=True,  # Policy definitions are Microsoft-managed
            )

        except Exception as e:
            self.logger.error("policy_assignment_parse_error", error=str(e))
            # Don't swallow parse errors - raise to surface issues
            raise


# Note: Comprehensive MITRE mappings will be in
# backend/app/mappers/azure_policy_mappings.py (200-300 lines)
# based on pattern matching and MITRE CTID Security Stack Mappings for Azure
