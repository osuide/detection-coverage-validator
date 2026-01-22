"""Microsoft Defender for Cloud security assessment scanner.

Discovers security assessments from Microsoft Defender for Cloud (formerly Azure Security Center).
Defender includes native MITRE ATT&CK mappings in assessment metadata.
"""

from typing import Any, Optional

import structlog

from app.models.detection import DetectionType
from app.scanners.base import BaseScanner, RawDetection

logger = structlog.get_logger()


class DefenderScanner(BaseScanner):
    """Scanner for Microsoft Defender for Cloud security assessments.

    Microsoft Defender for Cloud provides security assessments and recommendations.
    This scanner discovers security assessments and extracts native MITRE mappings.

    Security Architecture:
    - Uses Azure Resource Manager API via azure.mgmt.security
    - Authenticated via Workload Identity Federation (no static credentials)
    - Scans subscription-level security assessments
    """

    @property
    def detection_type(self) -> DetectionType:
        return DetectionType.AZURE_DEFENDER

    async def scan(
        self,
        regions: list[str],
        options: Optional[dict[str, Any]] = None,
    ) -> list[RawDetection]:
        """Scan Azure subscription for Defender security assessments.

        Args:
            regions: Ignored - Defender is subscription-level, not regional
            options: Must contain subscription_id

        Returns:
            List of RawDetection objects (with native MITRE tags)

        Raises:
            ValueError: If subscription_id not provided
            Exception: For Azure API errors (logged and re-raised)
        """
        if not options or "subscription_id" not in options:
            raise ValueError("subscription_id required for Azure Defender scanning")

        subscription_id = options["subscription_id"]
        self.logger.info("scanning_defender", subscription_id=subscription_id)

        all_detections = []

        try:
            from azure.mgmt.security.aio import SecurityCenter
            from azure.core.exceptions import (
                AzureError,
                HttpResponseError,
                ResourceNotFoundError,
            )

            # Create Security Center client with WIF credentials
            # self.session is async ClientAssertionCredential from azure_wif_service
            # CRITICAL: Must use async client from .aio module with async credential
            async with SecurityCenter(
                credential=self.session, subscription_id=subscription_id
            ) as client:
                # Scan security assessments
                assessments = await self._scan_assessments(client, subscription_id)
                all_detections.extend(assessments)

            self.logger.info(
                "defender_scan_complete",
                subscription_id=subscription_id,
                assessment_count=len(assessments),
            )

        except ResourceNotFoundError as e:
            # Defender not enabled - log but don't raise
            self.logger.warning(
                "defender_not_enabled", subscription_id=subscription_id, error=str(e)
            )

        except HttpResponseError as e:
            # Permission denied or other HTTP error
            self.logger.error(
                "defender_http_error",
                subscription_id=subscription_id,
                status_code=e.status_code if hasattr(e, "status_code") else None,
                error=str(e),
            )
            raise

        except AzureError as e:
            # Other Azure SDK errors
            self.logger.error(
                "defender_azure_error", subscription_id=subscription_id, error=str(e)
            )
            raise

        except ImportError:
            self.logger.error("security_center_client_not_installed")
            raise

        return all_detections

    async def _scan_assessments(
        self, client: Any, subscription_id: str
    ) -> list[RawDetection]:
        """Scan for Defender security assessments.

        Args:
            client: SecurityCenter instance
            subscription_id: Azure subscription ID

        Returns:
            List of RawDetection objects for each assessment
        """
        detections = []

        try:
            # Use async iteration with the async Azure SDK client
            assessments = []
            async for assessment in client.assessments.list():
                assessments.append(assessment)

            # Process each assessment
            for assessment in assessments:
                # Extract assessment details
                assessment_id = assessment.name if hasattr(assessment, "name") else None
                display_name = (
                    assessment.display_name
                    if hasattr(assessment, "display_name")
                    else "Unknown Assessment"
                )
                status = (
                    assessment.status.code
                    if hasattr(assessment, "status")
                    and hasattr(assessment.status, "code")
                    else "Unknown"
                )
                severity = (
                    assessment.metadata.severity
                    if hasattr(assessment, "metadata")
                    and hasattr(assessment.metadata, "severity")
                    else "Unknown"
                )

                # Extract native MITRE tags from additionalData (if present)
                mitre_tags = []
                if hasattr(assessment, "additional_data"):
                    additional_data = assessment.additional_data or {}
                    if isinstance(additional_data, dict):
                        # Defender may include MITRE tags in various fields
                        mitre_tags = additional_data.get("mitreTechniques", [])

                # Build raw_config with all assessment metadata
                raw_config = {
                    "assessmentId": assessment_id,
                    "displayName": display_name,
                    "status": status,
                    "severity": severity,
                    "subscriptionId": subscription_id,
                    "mitreTechniques": mitre_tags,  # Native MITRE tags (if present)
                }

                # Add resource details if available
                if hasattr(assessment, "resource_details"):
                    resource_details = assessment.resource_details
                    if hasattr(resource_details, "id"):
                        raw_config["resourceId"] = resource_details.id

                # Create detection object
                # source_arn format: arn:azure:defender:assessment/{assessmentId}
                detection = RawDetection(
                    name=display_name,
                    source_arn=f"arn:azure:defender:assessment/{assessment_id}",
                    enabled=status.lower() == "unhealthy",  # Unhealthy = active finding
                    raw_config=raw_config,
                )

                detections.append(detection)

            self.logger.debug(
                "assessments_processed",
                subscription_id=subscription_id,
                count=len(detections),
            )

        except Exception as e:
            self.logger.error(
                "assessment_processing_error",
                subscription_id=subscription_id,
                error=str(e),
            )
            raise

        return detections
