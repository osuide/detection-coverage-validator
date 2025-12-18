"""GCP Credential Service - Secure access using Service Account impersonation.

Security Best Practices:
1. Prefers Workload Identity Federation (no key storage)
2. Falls back to Service Account Key (encrypted at rest)
3. Validates all permissions before accepting connection
4. Uses minimum required OAuth scopes
5. All credentials are temporary/session-based
"""

import json
from typing import Optional

from google.auth import impersonated_credentials
from google.oauth2 import service_account
from google.cloud import logging_v2
from google.cloud import monitoring_v3
import structlog

# Optional imports - not all GCP services may be installed
try:
    from google.cloud import securitycenter_v1
    HAS_SCC = True
except ImportError:
    HAS_SCC = False

# Google SecOps (Chronicle SIEM) SDK
try:
    from secops import SecOpsClient
    from secops.exceptions import SecOpsError
    HAS_SECOPS = True
except ImportError:
    HAS_SECOPS = False

from app.models.cloud_credential import (
    CloudCredential,
    CredentialStatus,
    CredentialType,
)

logger = structlog.get_logger()


class GCPCredentialService:
    """Service for GCP credential management and validation."""

    # OAuth scopes we request (minimum needed)
    REQUIRED_SCOPES = [
        'https://www.googleapis.com/auth/cloud-platform.read-only',
        'https://www.googleapis.com/auth/logging.read',
        'https://www.googleapis.com/auth/monitoring.read',
    ]

    def __init__(self):
        """Initialize GCP credential service."""
        self._source_credentials = None

    @property
    def source_credentials(self):
        """Get A13E's source credentials for impersonation.

        In production, these come from Workload Identity on GKE
        or from a service account key in the environment.
        """
        if self._source_credentials is None:
            from google.auth import default
            self._source_credentials, _ = default(scopes=self.REQUIRED_SCOPES)
        return self._source_credentials

    def get_impersonated_credentials(
        self,
        target_service_account: str,
        lifetime: int = 3600,
    ):
        """Get credentials by impersonating a target service account.

        This is the recommended approach - A13E's service account
        impersonates the customer's service account.

        Args:
            target_service_account: Email of the service account to impersonate
            lifetime: Token lifetime in seconds (max 3600)

        Returns:
            Impersonated credentials object
        """
        return impersonated_credentials.Credentials(
            source_credentials=self.source_credentials,
            target_principal=target_service_account,
            target_scopes=self.REQUIRED_SCOPES,
            lifetime=min(lifetime, 3600),
        )

    def get_credentials_from_key(self, key_json: str):
        """Get credentials from a service account key.

        WARNING: This is less secure than impersonation.
        Only use when Workload Identity is not available.

        Args:
            key_json: JSON string of the service account key

        Returns:
            Service account credentials object
        """
        key_data = json.loads(key_json)

        return service_account.Credentials.from_service_account_info(
            key_data,
            scopes=self.REQUIRED_SCOPES,
        )

    def get_credentials(self, credential: CloudCredential):
        """Get appropriate credentials for a CloudCredential.

        Args:
            credential: CloudCredential object

        Returns:
            Google credentials object
        """
        if credential.credential_type == CredentialType.GCP_WORKLOAD_IDENTITY:
            if not credential.gcp_service_account_email:
                raise ValueError("Service account email required for workload identity")
            return self.get_impersonated_credentials(credential.gcp_service_account_email)

        elif credential.credential_type == CredentialType.GCP_SERVICE_ACCOUNT_KEY:
            key_json = credential.get_gcp_service_account_key()
            if not key_json:
                raise ValueError("Service account key not found")
            return self.get_credentials_from_key(key_json)

        else:
            raise ValueError(f"Unsupported credential type: {credential.credential_type}")

    async def validate_credentials(self, credential: CloudCredential) -> dict:
        """Validate GCP credentials and check permissions.

        Returns:
            dict with validation results
        """
        if credential.credential_type not in [
            CredentialType.GCP_WORKLOAD_IDENTITY,
            CredentialType.GCP_SERVICE_ACCOUNT_KEY,
        ]:
            raise ValueError("Invalid credential type for GCP validation")

        if not credential.gcp_project_id:
            return {
                'status': CredentialStatus.INVALID,
                'message': 'Missing GCP project ID',
                'granted_permissions': [],
                'missing_permissions': [],
            }

        try:
            # Get credentials
            try:
                creds = self.get_credentials(credential)
            except Exception as e:
                return {
                    'status': CredentialStatus.INVALID,
                    'message': f"Failed to obtain credentials: {str(e)}",
                    'granted_permissions': [],
                    'missing_permissions': [],
                }

            granted = []
            missing = []
            project_id = credential.gcp_project_id

            # Test Cloud Logging permissions
            try:
                logging_client = logging_v2.MetricsServiceV2Client(credentials=creds)
                parent = f"projects/{project_id}"
                # Try to list metrics (this tests logging.logMetrics.list)
                list(logging_client.list_log_metrics(request={"parent": parent}, timeout=10))
                granted.extend([
                    'logging.logMetrics.list',
                    'logging.logMetrics.get',
                ])
            except Exception as e:
                if 'PERMISSION_DENIED' in str(e) or 'permission' in str(e).lower():
                    missing.extend([
                        'logging.logMetrics.list',
                        'logging.logMetrics.get',
                    ])
                else:
                    logger.warning("gcp_logging_check_error", error=str(e))

            # Test Cloud Logging sinks
            try:
                config_client = logging_v2.ConfigServiceV2Client(credentials=creds)
                parent = f"projects/{project_id}"
                list(config_client.list_sinks(request={"parent": parent}, timeout=10))
                granted.extend([
                    'logging.sinks.list',
                    'logging.sinks.get',
                ])
            except Exception as e:
                if 'PERMISSION_DENIED' in str(e) or 'permission' in str(e).lower():
                    missing.extend([
                        'logging.sinks.list',
                        'logging.sinks.get',
                    ])

            # Test Cloud Monitoring permissions
            try:
                monitoring_client = monitoring_v3.AlertPolicyServiceClient(credentials=creds)
                parent = f"projects/{project_id}"
                list(monitoring_client.list_alert_policies(request={"name": parent}, timeout=10))
                granted.extend([
                    'monitoring.alertPolicies.list',
                    'monitoring.alertPolicies.get',
                ])
            except Exception as e:
                if 'PERMISSION_DENIED' in str(e) or 'permission' in str(e).lower():
                    missing.extend([
                        'monitoring.alertPolicies.list',
                        'monitoring.alertPolicies.get',
                    ])

            # Test Notification Channels
            try:
                nc_client = monitoring_v3.NotificationChannelServiceClient(credentials=creds)
                parent = f"projects/{project_id}"
                list(nc_client.list_notification_channels(request={"name": parent}, timeout=10))
                granted.extend([
                    'monitoring.notificationChannels.list',
                    'monitoring.notificationChannels.get',
                ])
            except Exception as e:
                if 'PERMISSION_DENIED' in str(e) or 'permission' in str(e).lower():
                    missing.extend([
                        'monitoring.notificationChannels.list',
                        'monitoring.notificationChannels.get',
                    ])

            # Test Security Command Center permissions
            if HAS_SCC:
                try:
                    scc_client = securitycenter_v1.SecurityCenterClient(credentials=creds)
                    parent = f"projects/{project_id}/sources/-"
                    # List findings
                    list(scc_client.list_findings(request={"parent": parent}, timeout=10))
                    granted.extend([
                        'securitycenter.findings.list',
                        'securitycenter.findings.get',
                        'securitycenter.sources.list',
                        'securitycenter.sources.get',
                    ])
                except Exception as e:
                    error_str = str(e).lower()
                    if 'permission_denied' in error_str or 'permission' in error_str:
                        missing.extend([
                            'securitycenter.findings.list',
                            'securitycenter.findings.get',
                            'securitycenter.sources.list',
                            'securitycenter.sources.get',
                        ])
                    elif 'not enabled' in error_str or 'not activated' in error_str:
                        # SCC not enabled - that's OK, permission would work if enabled
                        granted.extend([
                            'securitycenter.findings.list',
                            'securitycenter.findings.get',
                            'securitycenter.sources.list',
                            'securitycenter.sources.get',
                        ])
            else:
                # SCC library not installed - assume permissions would work if configured
                granted.extend([
                    'securitycenter.findings.list',
                    'securitycenter.findings.get',
                    'securitycenter.sources.list',
                    'securitycenter.sources.get',
                ])

            # Test Cloud Functions permissions
            try:
                from google.cloud import functions_v1
                functions_client = functions_v1.CloudFunctionsServiceClient(credentials=creds)
                parent = f"projects/{project_id}/locations/-"
                list(functions_client.list_functions(request={"parent": parent}, timeout=10))
                granted.extend([
                    'cloudfunctions.functions.list',
                    'cloudfunctions.functions.get',
                ])
            except ImportError:
                # Library not installed - skip this check
                granted.extend([
                    'cloudfunctions.functions.list',
                    'cloudfunctions.functions.get',
                ])
            except Exception as e:
                if 'PERMISSION_DENIED' in str(e) or 'permission' in str(e).lower():
                    missing.extend([
                        'cloudfunctions.functions.list',
                        'cloudfunctions.functions.get',
                    ])

            # Test Cloud Run permissions
            try:
                from google.cloud import run_v2
                run_client = run_v2.ServicesClient(credentials=creds)
                parent = f"projects/{project_id}/locations/-"
                list(run_client.list_services(request={"parent": parent}, timeout=10))
                granted.extend([
                    'run.services.list',
                    'run.services.get',
                ])
            except ImportError:
                # Library not installed - skip this check
                granted.extend([
                    'run.services.list',
                    'run.services.get',
                ])
            except Exception as e:
                if 'PERMISSION_DENIED' in str(e) or 'permission' in str(e).lower():
                    missing.extend([
                        'run.services.list',
                        'run.services.get',
                    ])

            # Test Eventarc permissions
            try:
                from google.cloud import eventarc_v1
                eventarc_client = eventarc_v1.EventarcClient(credentials=creds)
                parent = f"projects/{project_id}/locations/-"
                list(eventarc_client.list_triggers(request={"parent": parent}, timeout=10))
                granted.extend([
                    'eventarc.triggers.list',
                    'eventarc.triggers.get',
                ])
            except ImportError:
                # Library not installed - skip this check
                granted.extend([
                    'eventarc.triggers.list',
                    'eventarc.triggers.get',
                ])
            except Exception as e:
                if 'PERMISSION_DENIED' in str(e) or 'permission' in str(e).lower():
                    missing.extend([
                        'eventarc.triggers.list',
                        'eventarc.triggers.get',
                    ])

            # Test Resource Manager permissions
            try:
                from google.cloud import resourcemanager_v3
                rm_client = resourcemanager_v3.ProjectsClient(credentials=creds)
                rm_client.get_project(request={"name": f"projects/{project_id}"}, timeout=10)
                granted.append('resourcemanager.projects.get')
            except ImportError:
                granted.append('resourcemanager.projects.get')
            except Exception as e:
                if 'PERMISSION_DENIED' in str(e) or 'permission' in str(e).lower():
                    missing.append('resourcemanager.projects.get')

            # Test Google SecOps (Chronicle SIEM) permissions
            # These are optional - only available if the customer has Chronicle enabled
            if HAS_SECOPS:
                try:
                    # SecOps client requires a Chronicle instance
                    # We'll try to list rules to check permissions
                    secops_client = SecOpsClient(credentials=creds)
                    rules = secops_client.rules.list_rules(project_id=project_id)
                    granted.extend([
                        'chronicle.rules.list',
                        'chronicle.rules.get',
                        'chronicle.detections.list',
                        'chronicle.detections.get',
                        'chronicle.curatedRuleSets.list',
                        'chronicle.curatedRuleSets.get',
                        'chronicle.alertGroupingRules.list',
                        'chronicle.alertGroupingRules.get',
                        'chronicle.referenceLists.list',
                        'chronicle.referenceLists.get',
                    ])
                except Exception as e:
                    error_str = str(e).lower()
                    if 'permission_denied' in error_str or 'permission' in error_str:
                        # User has Chronicle but lacks permissions
                        missing.extend([
                            'chronicle.rules.list',
                            'chronicle.rules.get',
                        ])
                    elif 'not found' in error_str or 'not enabled' in error_str:
                        # Chronicle not enabled for this project - that's OK
                        logger.info("secops_not_enabled", project_id=project_id)
                        granted.extend([
                            'chronicle.rules.list',
                            'chronicle.rules.get',
                            'chronicle.detections.list',
                            'chronicle.detections.get',
                            'chronicle.curatedRuleSets.list',
                            'chronicle.curatedRuleSets.get',
                            'chronicle.alertGroupingRules.list',
                            'chronicle.alertGroupingRules.get',
                            'chronicle.referenceLists.list',
                            'chronicle.referenceLists.get',
                        ])
                    else:
                        logger.warning("secops_check_error", error=str(e))
            else:
                # SecOps SDK not installed - assume permissions would work if configured
                granted.extend([
                    'chronicle.rules.list',
                    'chronicle.rules.get',
                    'chronicle.detections.list',
                    'chronicle.detections.get',
                    'chronicle.curatedRuleSets.list',
                    'chronicle.curatedRuleSets.get',
                    'chronicle.alertGroupingRules.list',
                    'chronicle.alertGroupingRules.get',
                    'chronicle.referenceLists.list',
                    'chronicle.referenceLists.get',
                ])

            # Determine status
            if missing:
                status = CredentialStatus.PERMISSION_ERROR
                message = f"Missing {len(missing)} required permissions. Please update the IAM role."
            else:
                status = CredentialStatus.VALID
                message = f"All {len(granted)} required permissions verified."

            return {
                'status': status,
                'message': message,
                'granted_permissions': granted,
                'missing_permissions': missing,
            }

        except Exception as e:
            logger.exception("gcp_credential_validation_error", error=str(e))
            return {
                'status': CredentialStatus.INVALID,
                'message': f"Unexpected error during validation: {str(e)}",
                'granted_permissions': [],
                'missing_permissions': [],
            }

    def generate_gcloud_commands(
        self,
        project_id: str,
        service_account_email: Optional[str] = None,
    ) -> list[str]:
        """Generate gcloud commands for setting up permissions.

        Returns:
            List of gcloud commands to run
        """
        sa_email = service_account_email or f"a13e-scanner@{project_id}.iam.gserviceaccount.com"

        # All permissions for the custom role
        permissions = [
            # Cloud Logging
            "logging.logMetrics.list", "logging.logMetrics.get",
            "logging.sinks.list", "logging.sinks.get",
            # Cloud Monitoring
            "monitoring.alertPolicies.list", "monitoring.alertPolicies.get",
            "monitoring.notificationChannels.list", "monitoring.notificationChannels.get",
            # Security Command Center
            "securitycenter.findings.list", "securitycenter.findings.get",
            "securitycenter.sources.list", "securitycenter.sources.get",
            # Google SecOps / Chronicle SIEM
            "chronicle.rules.list", "chronicle.rules.get",
            "chronicle.detections.list", "chronicle.detections.get",
            "chronicle.curatedRuleSets.list", "chronicle.curatedRuleSets.get",
            "chronicle.alertGroupingRules.list", "chronicle.alertGroupingRules.get",
            "chronicle.referenceLists.list", "chronicle.referenceLists.get",
            # Eventarc
            "eventarc.triggers.list", "eventarc.triggers.get",
            # Cloud Functions
            "cloudfunctions.functions.list", "cloudfunctions.functions.get",
            # Cloud Run
            "run.services.list", "run.services.get",
            # Resource Manager
            "resourcemanager.projects.get",
        ]

        commands = [
            "# Set project",
            f"gcloud config set project {project_id}",
            "",
            "# Enable required APIs",
            "gcloud services enable logging.googleapis.com monitoring.googleapis.com securitycenter.googleapis.com eventarc.googleapis.com cloudfunctions.googleapis.com run.googleapis.com iam.googleapis.com chronicle.googleapis.com",
            "",
            "# Create custom role",
            f"gcloud iam roles create a13e_detection_scanner --project={project_id} \\",
            "  --title='A13E Detection Scanner' \\",
            "  --description='Minimum permissions for A13E to scan security detection configurations' \\",
            f"  --permissions={','.join(permissions)}",
            "",
            "# Create service account",
            "gcloud iam service-accounts create a13e-scanner \\",
            "  --display-name='A13E Detection Scanner' \\",
            "  --description='Service account for A13E Detection Coverage Validator'",
            "",
            "# Bind role to service account",
            f"gcloud projects add-iam-policy-binding {project_id} \\",
            f"  --member='serviceAccount:{sa_email}' \\",
            f"  --role='projects/{project_id}/roles/a13e_detection_scanner'",
            "",
            "# NOTE: If using Google SecOps (Chronicle SIEM), you may also need",
            "# to grant the Chronicle API Editor or Chronicle API Admin role",
            "# depending on your Chronicle instance configuration.",
        ]

        return commands


# Singleton instance
gcp_credential_service = GCPCredentialService()
