"""Cloud Credential API endpoints.

Provides secure credential management for connecting AWS and GCP accounts.
"""

from pathlib import Path as _Path
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import AuthContext, get_client_ip, require_role, require_scope
from app.models.user import UserRole, AuditLog, AuditLogAction
from app.models.cloud_account import CloudAccount, CloudProvider
from app.models.cloud_credential import (
    CloudCredential,
    CredentialType,
    CredentialStatus,
    AWS_IAM_POLICY,
    AWS_REQUIRED_PERMISSIONS,
    GCP_CUSTOM_ROLE,
    GCP_REQUIRED_PERMISSIONS,
    AZURE_REQUIRED_PERMISSIONS,
    PERMISSIONS_NOT_REQUESTED,
)
from app.services.aws_credential_service import aws_credential_service
from app.services.gcp_credential_service import gcp_credential_service
from app.services.gcp_wif_service import gcp_wif_service, GCPWIFError
from app.services.azure_wif_service import (
    AzureWIFConfiguration,
    AzureWIFError,
    validate_wif_configuration as validate_azure_wif,
)

logger = structlog.get_logger()
router = APIRouter()


# === Request/Response Schemas ===


class AWSCredentialCreate(BaseModel):
    """Request to create AWS credential."""

    cloud_account_id: UUID
    role_arn: str = Field(..., pattern=r"^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$")

    @field_validator("role_arn")
    @classmethod
    def validate_role_arn(cls, v: str) -> str:
        if not v.startswith("arn:aws:iam::"):
            raise ValueError("Invalid AWS role ARN format")
        return v


class GCPCredentialCreate(BaseModel):
    """Request to create GCP credential.

    Only Workload Identity Federation (WIF) is supported.
    Service account keys are NOT accepted for security reasons.

    A13E is a security tool - using JSON keys would contradict our mission.
    WIF provides keyless, short-lived credentials with no secrets to manage.
    """

    cloud_account_id: UUID
    credential_type: str = Field(
        default="gcp_workload_identity",
        pattern="^gcp_workload_identity$",  # Only WIF accepted
    )
    service_account_email: str  # Required for WIF

    # WIF-specific fields
    pool_id: str = Field(default="a13e-pool", description="WIF pool ID")
    provider_id: str = Field(default="a13e-aws", description="WIF provider ID")
    pool_location: str = Field(default="global", description="WIF pool location")

    @field_validator("credential_type")
    @classmethod
    def validate_wif_only(cls, v: str) -> str:
        """Ensure only WIF credentials are accepted.

        Service account keys are rejected for security reasons.
        A13E practices what we preach - no stored credentials.
        """
        if v != "gcp_workload_identity":
            raise ValueError(
                "Service account keys are not accepted for security reasons. "
                "Use Workload Identity Federation (WIF) instead. "
                "Run the WIF setup script to configure keyless authentication."
            )
        return v


class GCPWIFValidationResponse(BaseModel):
    """Response from GCP WIF validation."""

    valid: bool
    message: str
    steps_completed: list[str]
    steps_failed: list[str]


class CredentialResponse(BaseModel):
    """Credential status response."""

    id: UUID
    cloud_account_id: UUID
    credential_type: str
    status: str
    status_message: Optional[str]
    last_validated_at: Optional[str]
    granted_permissions: Optional[list[str]]
    missing_permissions: Optional[list[str]]
    # AWS specific
    aws_role_arn: Optional[str]
    aws_external_id: Optional[str]
    # GCP specific
    gcp_project_id: Optional[str]
    gcp_service_account_email: Optional[str]


class SetupInstructionsResponse(BaseModel):
    """Setup instructions for connecting cloud account."""

    provider: str
    a13e_aws_account_id: str  # A13E's AWS account ID for trust policy/WIF
    external_id: Optional[str]  # For AWS
    iam_policy: Optional[dict]  # For AWS
    custom_role: Optional[dict]  # For GCP
    required_permissions: list[dict]
    not_requested: list[str]
    cloudformation_template_url: Optional[str]
    terraform_module_url: Optional[str]
    gcloud_commands: Optional[list[str]]
    manual_steps: list[str]


class ValidationResponse(BaseModel):
    """Credential validation response."""

    status: str
    message: str
    granted_permissions: list[str]
    missing_permissions: list[str]


# === Endpoints ===


@router.get(
    "/setup/{cloud_account_id}",
    response_model=SetupInstructionsResponse,
    dependencies=[Depends(require_scope("read:credentials"))],
)
async def get_setup_instructions(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get setup instructions for connecting a cloud account.

    Returns provider-specific instructions including:
    - IAM policy/custom role definition
    - Required permissions with explanations
    - CloudFormation/Terraform templates
    - Step-by-step manual instructions
    """
    # Get cloud account
    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    # Check for existing credential to get external ID
    result = await db.execute(
        select(CloudCredential).where(
            CloudCredential.cloud_account_id == cloud_account_id
        )
    )
    existing = result.scalar_one_or_none()

    if account.provider == CloudProvider.AWS:
        # Generate or get external ID
        external_id = (
            existing.aws_external_id
            if existing
            else CloudCredential.generate_external_id()
        )

        # If no existing credential, create placeholder with external ID
        if not existing:
            credential = CloudCredential(
                cloud_account_id=cloud_account_id,
                organization_id=auth.organization_id,
                credential_type=CredentialType.AWS_IAM_ROLE,
                aws_external_id=external_id,
                status=CredentialStatus.PENDING,
                created_by=auth.user.id,
            )
            db.add(credential)
            await db.commit()

        # Get A13E's AWS account ID for trust policy
        settings = get_settings()
        a13e_account_id = settings.a13e_aws_account_id

        return SetupInstructionsResponse(
            provider="aws",
            a13e_aws_account_id=a13e_account_id,
            external_id=external_id,
            iam_policy=AWS_IAM_POLICY,
            custom_role=None,
            required_permissions=AWS_REQUIRED_PERMISSIONS,
            not_requested=PERMISSIONS_NOT_REQUESTED["aws"],
            cloudformation_template_url="/api/v1/credentials/templates/aws/cloudformation",
            terraform_module_url="/api/v1/credentials/templates/aws/terraform",
            gcloud_commands=None,
            manual_steps=[
                "Go to AWS IAM Console → Policies → Create policy",
                "Click JSON tab and paste the IAM Policy JSON provided",
                "Name the policy 'A13E-DetectionScanner' and create it",
                "Go to IAM → Roles → Create role",
                "Select 'AWS account' as trusted entity type",
                f"Choose 'Another AWS account' and enter A13E's Account ID: {a13e_account_id}",
                "Check 'Require external ID' and enter the External ID shown above",
                "Click Next, search for and attach 'A13E-DetectionScanner' policy",
                "Name the role 'A13E-ReadOnly' and create it",
                "Copy the Role ARN and return here to complete setup",
            ],
        )

    elif account.provider == CloudProvider.GCP:
        gcloud_commands = gcp_credential_service.generate_gcloud_commands(
            project_id=account.account_id,
        )

        # Get A13E's AWS account ID for WIF setup
        settings = get_settings()
        a13e_account_id = settings.a13e_aws_account_id

        return SetupInstructionsResponse(
            provider="gcp",
            a13e_aws_account_id=a13e_account_id,
            external_id=None,
            iam_policy=None,
            custom_role=GCP_CUSTOM_ROLE,
            required_permissions=GCP_REQUIRED_PERMISSIONS,
            not_requested=PERMISSIONS_NOT_REQUESTED["gcp"],
            cloudformation_template_url=None,
            terraform_module_url="/api/v1/credentials/templates/gcp/terraform",
            gcloud_commands=[
                "# Option 1: Automated WIF setup (RECOMMENDED)",
                "curl -sL https://app.a13e.io/api/v1/credentials/templates/gcp/wif-setup -o gcp_wif_setup.sh",
                "chmod +x gcp_wif_setup.sh",
                f"./gcp_wif_setup.sh --project {account.account_id} --aws-account {a13e_account_id}",
                "",
                "# Option 2: Manual gcloud commands",
                *gcloud_commands,
            ],
            manual_steps=[
                "RECOMMENDED: Use Workload Identity Federation (WIF) for keyless authentication",
                "",
                "Option A - Automated Setup (Recommended):",
                "  1. Open Google Cloud Shell for your project",
                "  2. Download the setup script:",
                "     curl -sL https://app.a13e.io/api/v1/credentials/templates/gcp/wif-setup -o gcp_wif_setup.sh",
                "  3. Make it executable: chmod +x gcp_wif_setup.sh",
                f"  4. Run: ./gcp_wif_setup.sh --project {account.account_id} --aws-account {a13e_account_id}",
                "  5. Copy the output values and return here to complete setup",
                "",
                "Option B - Manual Setup via GCP Console:",
                "",
                "  Step 1: Enable Required APIs",
                "    • Go to APIs & Services → Library",
                "    • Enable: Cloud Logging, Cloud Monitoring, Security Command Center,",
                "      Eventarc, Cloud Functions, Cloud Run, IAM APIs",
                "",
                "  Step 2: Create Custom Role with Minimal Permissions",
                "    • Go to IAM & Admin → Roles → Create Role",
                "    • Name: 'A13E Detection Scanner' (ID: a13e_detection_scanner)",
                "    • Add permissions: logging.logMetrics.list, logging.sinks.list,",
                "      monitoring.alertPolicies.list, securitycenter.sources.list,",
                "      securitycenter.notificationconfigs.list, eventarc.triggers.list,",
                "      cloudfunctions.functions.list, run.services.list, resourcemanager.projects.get",
                "    • Create the role",
                "",
                "  Step 3: Create Service Account",
                "    • Go to IAM & Admin → Service Accounts → Create Service Account",
                "    • Name: 'a13e-scanner'",
                f"    • Email will be: a13e-scanner@{account.account_id}.iam.gserviceaccount.com",
                "",
                "  Step 4: Grant Custom Role to Service Account",
                "    • Go to IAM & Admin → IAM",
                f"    • Add principal: a13e-scanner@{account.account_id}.iam.gserviceaccount.com",
                f"    • Assign role: projects/{account.account_id}/roles/a13e_detection_scanner",
                "",
                "  Step 5: Set Up Workload Identity Federation",
                "    • Go to IAM & Admin → Workload Identity Federation",
                "    • Create Pool: Name 'a13e-pool'",
                "    • Add Provider: Select 'AWS', enter A13E's AWS Account ID shown above",
                "    • Configure attribute mapping for AWS",
                "",
                "  Step 6: Grant WIF Permission to Impersonate Service Account",
                "    • In the WIF pool, click 'Grant Access'",
                "    • Select the a13e-scanner service account",
                "    • Grant 'Workload Identity User' role",
                "",
                "  Step 7: Return here with the service account email to complete setup",
                "",
                "NOTE: Service account keys are NOT supported. WIF provides keyless, secure access.",
            ],
        )

    elif account.provider == CloudProvider.AZURE:
        # Get A13E's AWS account ID for WIF setup
        settings = get_settings()
        a13e_account_id = settings.a13e_aws_account_id

        return SetupInstructionsResponse(
            provider="azure",
            a13e_aws_account_id=a13e_account_id,
            external_id=None,
            iam_policy=None,
            custom_role=None,
            required_permissions=AZURE_REQUIRED_PERMISSIONS,
            not_requested=PERMISSIONS_NOT_REQUESTED["azure"],
            cloudformation_template_url=None,
            terraform_module_url=None,
            gcloud_commands=None,
            manual_steps=[
                "Azure uses Workload Identity Federation (WIF) for secure, keyless authentication.",
                "",
                "Option A - Automated Setup (Recommended):",
                "  1. Open Azure Cloud Shell (Bash) or a terminal with Azure CLI installed",
                "  2. Download the setup script:",
                "     curl -sL https://app.a13e.com/api/v1/credentials/templates/azure/wif-setup -o azure_wif_setup.sh",
                "  3. Make it executable: chmod +x azure_wif_setup.sh",
                f"  4. Run: ./azure_wif_setup.sh --subscription {account.account_id}",
                "  5. Copy the Tenant ID and Client ID from the output",
                "  6. Return here to enter the credentials and complete setup",
                "",
                "Option B - Manual Setup via Azure Portal:",
                "",
                "  Step 1: Register an Azure AD Application",
                "    • Go to Azure Portal → Microsoft Entra ID → App registrations",
                "    • Click 'New registration'",
                "    • Name: 'A13E-DetectionScanner'",
                "    • Supported account types: 'Single tenant'",
                "    • No redirect URI needed",
                "    • Click 'Register'",
                "",
                "  Step 2: Configure Federated Identity Credential",
                "    • In your app registration, go to 'Certificates & secrets'",
                "    • Click 'Federated credentials' → 'Add credential'",
                "    • Scenario: 'Other issuer'",
                "    • Issuer: https://sts.eu-west-2.amazonaws.com",
                f"    • Subject: arn:aws:sts::{a13e_account_id}:assumed-role/A13E-Scanner-Role/*",
                "    • Audience: sts.amazonaws.com",
                "    • Name: 'A13E-AWS-Federation'",
                "    • Click 'Add'",
                "",
                "  Step 3: Assign Roles to the Application",
                "    • Go to your Subscription → Access control (IAM)",
                "    • Click 'Add' → 'Add role assignment'",
                "    • Role: 'Reader' → Next",
                "    • Assign access to: 'User, group, or service principal'",
                "    • Select: 'A13E-DetectionScanner' → Select → Review + assign",
                "    • Repeat for 'Security Reader' role",
                "",
                "  Step 4: Note the Required IDs",
                "    • Tenant ID: Found in Azure AD → Overview",
                "    • Client ID: Found in your App registration → Overview (Application ID)",
                f"    • Subscription ID: {account.account_id}",
                "",
                "  Step 5: Return here with Tenant ID and Client ID to complete setup",
            ],
        )

    raise HTTPException(status_code=400, detail="Unsupported provider")


@router.post(
    "/aws",
    response_model=CredentialResponse,
    dependencies=[Depends(require_scope("write:credentials"))],
)
async def create_aws_credential(
    request: Request,
    body: AWSCredentialCreate,
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Create or update AWS credential with role ARN."""
    # Verify account belongs to org
    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == body.cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    if account.provider != CloudProvider.AWS:
        raise HTTPException(status_code=400, detail="Account is not AWS")

    # Get existing credential or create new
    # M6b: Include organisation check when fetching credential
    result = await db.execute(
        select(CloudCredential).where(
            CloudCredential.cloud_account_id == body.cloud_account_id,
            CloudCredential.organization_id == auth.organization_id,
        )
    )
    credential = result.scalar_one_or_none()

    if credential:
        credential.aws_role_arn = body.role_arn
        credential.status = CredentialStatus.PENDING
    else:
        credential = CloudCredential(
            cloud_account_id=body.cloud_account_id,
            organization_id=auth.organization_id,
            credential_type=CredentialType.AWS_IAM_ROLE,
            aws_role_arn=body.role_arn,
            aws_external_id=CloudCredential.generate_external_id(),
            status=CredentialStatus.PENDING,
            created_by=auth.user.id,
        )
        db.add(credential)

    await db.commit()
    await db.refresh(credential)

    # Audit log
    audit_log = AuditLog(
        organization_id=auth.organization_id,
        user_id=auth.user.id,
        action=AuditLogAction.ORG_SETTINGS_UPDATED,
        resource_type="cloud_credential",
        resource_id=str(credential.id),
        details={
            "action": "aws_credential_created",
            "role_arn": body.role_arn[:50] + "...",
        },
        ip_address=get_client_ip(request),
        success=True,
    )
    db.add(audit_log)
    await db.commit()

    return _credential_to_response(credential)


@router.post(
    "/gcp",
    response_model=CredentialResponse,
    dependencies=[Depends(require_scope("write:credentials"))],
)
async def create_gcp_credential(
    request: Request,
    body: GCPCredentialCreate,
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Create or update GCP credential.

    For WIF (recommended): Provide service_account_email, pool_id, provider_id.
    Service account keys are DEPRECATED for security reasons.
    """
    # Verify account belongs to org
    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == body.cloud_account_id,
            CloudAccount.organization_id == auth.organization_id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise HTTPException(status_code=404, detail="Cloud account not found")

    if account.provider != CloudProvider.GCP:
        raise HTTPException(status_code=400, detail="Account is not GCP")

    # Get existing credential or create new
    # M6b: Include organisation check when fetching credential
    result = await db.execute(
        select(CloudCredential).where(
            CloudCredential.cloud_account_id == body.cloud_account_id,
            CloudCredential.organization_id == auth.organization_id,
        )
    )
    credential = result.scalar_one_or_none()

    # GCP only accepts WIF - credential_type is validated by Pydantic
    cred_type = CredentialType.GCP_WORKLOAD_IDENTITY

    if credential:
        # Update existing credential to WIF
        credential.credential_type = cred_type
        credential.gcp_project_id = account.account_id
        credential.gcp_service_account_email = body.service_account_email
        credential.gcp_workload_identity_pool = body.pool_id
        credential.gcp_wif_provider_id = body.provider_id
        credential.gcp_wif_pool_location = body.pool_location
        # Clear any legacy SA key if present
        credential._encrypted_key = None
        credential.status = CredentialStatus.PENDING
    else:
        credential = CloudCredential(
            cloud_account_id=body.cloud_account_id,
            organization_id=auth.organization_id,
            credential_type=cred_type,
            gcp_project_id=account.account_id,
            gcp_service_account_email=body.service_account_email,
            gcp_workload_identity_pool=body.pool_id,
            gcp_wif_provider_id=body.provider_id,
            gcp_wif_pool_location=body.pool_location,
            status=CredentialStatus.PENDING,
            created_by=auth.user.id,
        )
        db.add(credential)

    await db.commit()
    await db.refresh(credential)

    # Audit log
    audit_log = AuditLog(
        organization_id=auth.organization_id,
        user_id=auth.user.id,
        action=AuditLogAction.ORG_SETTINGS_UPDATED,
        resource_type="cloud_credential",
        resource_id=str(credential.id),
        details={
            "action": "gcp_credential_created",
            "type": "gcp_workload_identity",
            "service_account": body.service_account_email,
            "wif_pool_id": body.pool_id,
            "wif_provider_id": body.provider_id,
        },
        ip_address=get_client_ip(request),
        success=True,
    )
    db.add(audit_log)
    await db.commit()

    return _credential_to_response(credential)


@router.post(
    "/gcp/wif/validate/{cloud_account_id}",
    response_model=GCPWIFValidationResponse,
    dependencies=[Depends(require_scope("write:credentials"))],
)
async def validate_gcp_wif(
    cloud_account_id: UUID,
    request: Request,
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Validate GCP Workload Identity Federation configuration.

    Tests the full WIF flow:
    1. Get AWS OIDC token
    2. Exchange for GCP credentials
    3. Impersonate service account
    4. Verify permissions
    """
    # Get credential
    result = await db.execute(
        select(CloudCredential).where(
            CloudCredential.cloud_account_id == cloud_account_id,
            CloudCredential.organization_id == auth.organization_id,
        )
    )
    credential = result.scalar_one_or_none()
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    if credential.credential_type != CredentialType.GCP_WORKLOAD_IDENTITY:
        raise HTTPException(
            status_code=400,
            detail="Credential is not WIF type. Use standard validation endpoint.",
        )

    # Get WIF configuration
    wif_config = credential.get_wif_configuration()
    if not wif_config:
        raise HTTPException(
            status_code=400,
            detail="Incomplete WIF configuration. Missing project_id or service_account_email.",
        )

    # Validate WIF configuration
    try:
        validation_result = await gcp_wif_service.validate_wif_configuration(wif_config)
    except GCPWIFError as e:
        logger.error(
            "wif_validation_error",
            cloud_account_id=str(cloud_account_id),
            error=str(e),
        )
        return GCPWIFValidationResponse(
            valid=False,
            message=f"WIF validation error: {str(e)}",
            steps_completed=[],
            steps_failed=["validation"],
        )

    # Update credential status based on validation
    from datetime import datetime, timezone

    if validation_result["valid"]:
        credential.status = CredentialStatus.VALID
        credential.status_message = "WIF configuration validated successfully"
    else:
        credential.status = CredentialStatus.INVALID
        credential.status_message = validation_result["message"]

    credential.last_validated_at = datetime.now(timezone.utc)
    await db.commit()

    # Audit log
    audit_log = AuditLog(
        organization_id=auth.organization_id,
        user_id=auth.user.id,
        action=AuditLogAction.ORG_SETTINGS_UPDATED,
        resource_type="cloud_credential",
        resource_id=str(credential.id),
        details={
            "action": "wif_validated",
            "valid": validation_result["valid"],
            "steps_completed": validation_result["steps_completed"],
        },
        ip_address=get_client_ip(request),
        success=validation_result["valid"],
    )
    db.add(audit_log)
    await db.commit()

    return GCPWIFValidationResponse(
        valid=validation_result["valid"],
        message=validation_result["message"],
        steps_completed=validation_result["steps_completed"],
        steps_failed=validation_result["steps_failed"],
    )


@router.post(
    "/validate/{cloud_account_id}",
    response_model=ValidationResponse,
    dependencies=[Depends(require_scope("write:credentials"))],
)
async def validate_credential(
    cloud_account_id: UUID,
    request: Request,
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Validate a credential and check permissions."""
    from datetime import datetime, timezone

    # Get credential (for AWS/GCP)
    result = await db.execute(
        select(CloudCredential).where(
            CloudCredential.cloud_account_id == cloud_account_id,
            CloudCredential.organization_id == auth.organization_id,
        )
    )
    credential = result.scalar_one_or_none()

    # If no credential found, check if this is an Azure account
    # Azure stores WIF config on the CloudAccount itself, not in CloudCredential
    if not credential:
        account_result = await db.execute(
            select(CloudAccount).where(
                CloudAccount.id == cloud_account_id,
                CloudAccount.organization_id == auth.organization_id,
            )
        )
        account = account_result.scalar_one_or_none()

        if not account:
            raise HTTPException(status_code=404, detail="Account not found")

        if account.provider != CloudProvider.AZURE:
            raise HTTPException(status_code=404, detail="Credential not found")

        # Azure account - validate WIF config stored on account
        wif_data = account.azure_workload_identity_config
        if not wif_data:
            raise HTTPException(
                status_code=400,
                detail="Azure WIF configuration not set. Please configure Tenant ID and Client ID.",
            )

        try:
            azure_wif_config = AzureWIFConfiguration.from_dict(wif_data)
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid Azure WIF configuration: {e}",
            )

        try:
            wif_result = await validate_azure_wif(azure_wif_config)
            if wif_result["valid"]:
                validation = {
                    "status": CredentialStatus.VALID,
                    "message": wif_result["message"],
                    "granted_permissions": [],
                    "missing_permissions": [],
                }
                account.azure_enabled = True
            else:
                validation = {
                    "status": CredentialStatus.INVALID,
                    "message": wif_result["message"],
                    "granted_permissions": [],
                    "missing_permissions": [],
                }
                account.azure_enabled = False
        except AzureWIFError as e:
            validation = {
                "status": CredentialStatus.INVALID,
                "message": f"Azure WIF validation error: {str(e)}",
                "granted_permissions": [],
                "missing_permissions": [],
            }
            account.azure_enabled = False

        account.updated_at = datetime.now(timezone.utc)
        await db.commit()

        # Audit log for Azure
        audit_log = AuditLog(
            organization_id=auth.organization_id,
            user_id=auth.user.id,
            action=AuditLogAction.ORG_SETTINGS_UPDATED,
            resource_type="cloud_account",
            resource_id=str(account.id),
            details={
                "action": "azure_wif_validated",
                "status": validation["status"].value,
                "provider": "azure",
            },
            ip_address=get_client_ip(request),
            success=validation["status"] == CredentialStatus.VALID,
        )
        db.add(audit_log)
        await db.commit()

        return ValidationResponse(
            status=validation["status"].value,
            message=validation["message"],
            granted_permissions=validation["granted_permissions"],
            missing_permissions=validation["missing_permissions"],
        )

    # AWS/GCP: Validate based on credential type
    if credential.credential_type == CredentialType.AWS_IAM_ROLE:
        validation = await aws_credential_service.validate_credentials(credential)
    elif credential.credential_type == CredentialType.GCP_WORKLOAD_IDENTITY:
        # Use WIF service for WIF credentials (runs on AWS ECS)
        wif_config = credential.get_wif_configuration()
        if not wif_config:
            raise HTTPException(
                status_code=400,
                detail="Incomplete WIF configuration. Missing project_id or service_account_email.",
            )
        try:
            wif_result = await gcp_wif_service.validate_wif_configuration(wif_config)
            # Convert WIF result to standard validation format
            if wif_result["valid"]:
                validation = {
                    "status": CredentialStatus.VALID,
                    "message": wif_result["message"],
                    "granted_permissions": [],  # WIF validation doesn't check permissions
                    "missing_permissions": [],
                }
            else:
                validation = {
                    "status": CredentialStatus.INVALID,
                    "message": wif_result["message"],
                    "granted_permissions": [],
                    "missing_permissions": [],
                }
        except GCPWIFError as e:
            validation = {
                "status": CredentialStatus.INVALID,
                "message": f"WIF validation error: {str(e)}",
                "granted_permissions": [],
                "missing_permissions": [],
            }
    elif credential.credential_type == CredentialType.GCP_SERVICE_ACCOUNT_KEY:
        # Legacy SA key validation (deprecated)
        validation = await gcp_credential_service.validate_credentials(credential)
    else:
        raise HTTPException(status_code=400, detail="Unknown credential type")

    # Update credential status
    credential.status = validation["status"]
    credential.status_message = validation["message"]
    credential.last_validated_at = datetime.now(timezone.utc)
    credential.granted_permissions = validation["granted_permissions"]
    credential.missing_permissions = validation["missing_permissions"]

    await db.commit()

    # Audit log
    audit_log = AuditLog(
        organization_id=auth.organization_id,
        user_id=auth.user.id,
        action=AuditLogAction.ORG_SETTINGS_UPDATED,
        resource_type="cloud_credential",
        resource_id=str(credential.id),
        details={
            "action": "credential_validated",
            "status": validation["status"].value,
            "missing_count": len(validation["missing_permissions"]),
        },
        ip_address=get_client_ip(request),
        success=validation["status"] == CredentialStatus.VALID,
    )
    db.add(audit_log)
    await db.commit()

    return ValidationResponse(
        status=validation["status"].value,
        message=validation["message"],
        granted_permissions=validation["granted_permissions"],
        missing_permissions=validation["missing_permissions"],
    )


@router.get(
    "/{cloud_account_id}",
    response_model=CredentialResponse,
    dependencies=[Depends(require_scope("read:credentials"))],
)
async def get_credential(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(
        require_role(UserRole.MEMBER, UserRole.ADMIN, UserRole.OWNER)
    ),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get credential status for a cloud account."""
    # Security: Check account-level ACL (CWE-639 fix)
    if not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    result = await db.execute(
        select(CloudCredential).where(
            CloudCredential.cloud_account_id == cloud_account_id,
            CloudCredential.organization_id == auth.organization_id,
        )
    )
    credential = result.scalar_one_or_none()

    # If no credential found, check if this is an Azure account
    # Azure stores WIF config on the CloudAccount itself, not in CloudCredential
    if not credential:
        account_result = await db.execute(
            select(CloudAccount).where(
                CloudAccount.id == cloud_account_id,
                CloudAccount.organization_id == auth.organization_id,
            )
        )
        account = account_result.scalar_one_or_none()

        if account and account.provider == CloudProvider.AZURE:
            # Return synthetic credential response for Azure
            wif_config = account.azure_workload_identity_config or {}
            has_config = bool(
                wif_config.get("tenant_id") and wif_config.get("client_id")
            )
            return CredentialResponse(
                id=account.id,  # Use account ID as credential ID for Azure
                cloud_account_id=account.id,
                credential_type="azure_workload_identity",
                status=(
                    "valid"
                    if account.azure_enabled
                    else ("pending" if has_config else "not_configured")
                ),
                status_message=(
                    "Azure WIF configured and validated"
                    if account.azure_enabled
                    else (
                        "Azure WIF configured, awaiting validation"
                        if has_config
                        else "Azure WIF not configured"
                    )
                ),
                last_validated_at=(
                    account.updated_at.isoformat() if account.updated_at else None
                ),
                granted_permissions=[],
                missing_permissions=[],
                aws_role_arn=None,
                aws_external_id=None,
                gcp_project_id=None,
                gcp_service_account_email=None,
            )

        raise HTTPException(status_code=404, detail="Credential not found")

    return _credential_to_response(credential)


@router.delete(
    "/{cloud_account_id}",
    dependencies=[Depends(require_scope("write:credentials"))],
)
async def delete_credential(
    cloud_account_id: UUID,
    request: Request,
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a credential."""
    # Security: Check account-level ACL (CWE-639 fix)
    if not auth.can_access_account(cloud_account_id):
        raise HTTPException(
            status_code=403, detail="Access denied to this cloud account"
        )

    result = await db.execute(
        select(CloudCredential).where(
            CloudCredential.cloud_account_id == cloud_account_id,
            CloudCredential.organization_id == auth.organization_id,
        )
    )
    credential = result.scalar_one_or_none()
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    await db.delete(credential)

    # Audit log
    audit_log = AuditLog(
        organization_id=auth.organization_id,
        user_id=auth.user.id,
        action=AuditLogAction.ORG_SETTINGS_UPDATED,
        resource_type="cloud_credential",
        resource_id=str(credential.id),
        details={"action": "credential_deleted"},
        ip_address=get_client_ip(request),
        success=True,
    )
    db.add(audit_log)
    await db.commit()

    return {"message": "Credential deleted"}


# === Template Endpoints ===


# === Template Helpers ===

# Resolve template directory once at module load (absolute path for security)
_TEMPLATE_DIR = (_Path(__file__).parent.parent.parent / "templates").resolve()

# Explicit allowlist of permitted templates (defense in depth)
_ALLOWED_TEMPLATES = {
    "aws_cloudformation.yaml",
    "terraform/aws/main.tf",
    "terraform/gcp/main.tf",  # WIF-based setup
    "gcp_wif_setup.sh",
    "azure_wif_setup.sh",
}


def _read_template(relative_path: str) -> str:
    """Safely read a template file with path traversal protection.

    Args:
        relative_path: Path relative to the templates directory

    Returns:
        Template file contents

    Raises:
        HTTPException 404: If template not found or not in allowlist
        HTTPException 403: If path traversal attempt detected
    """
    # Security: Check allowlist first (defense in depth)
    if relative_path not in _ALLOWED_TEMPLATES:
        logger.warning(
            "template_not_in_allowlist",
            requested_path=relative_path,
        )
        raise HTTPException(
            status_code=404,
            detail="Template not found",
        )

    # Resolve the full path
    template_path = (_TEMPLATE_DIR / relative_path).resolve()

    # Security: Ensure the resolved path is within the template directory
    if not str(template_path).startswith(str(_TEMPLATE_DIR)):
        logger.warning(
            "path_traversal_attempt",
            requested_path=relative_path,
            resolved_path=str(template_path),
        )
        raise HTTPException(
            status_code=403,
            detail="Invalid template path",
        )

    if not template_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Template not found: {relative_path}",
        )

    return template_path.read_text()


@router.get("/templates/aws/cloudformation", response_class=PlainTextResponse)
async def get_aws_cloudformation_template() -> str:
    """Download AWS CloudFormation template."""
    return _read_template("aws_cloudformation.yaml")


@router.get("/templates/aws/terraform", response_class=PlainTextResponse)
async def get_aws_terraform_template() -> str:
    """Download AWS Terraform module."""
    return _read_template("terraform/aws/main.tf")


@router.get("/templates/gcp/terraform", response_class=PlainTextResponse)
async def get_gcp_terraform_template() -> str:
    """Download GCP Terraform module."""
    return _read_template("terraform/gcp/main.tf")


@router.get("/templates/gcp/setup-script", response_class=PlainTextResponse)
async def get_gcp_setup_script() -> str:
    """Download GCP Workload Identity Federation setup script.

    Uses WIF for keyless authentication from AWS to GCP.
    No service account keys required.

    Usage:
        chmod +x gcp_wif_setup.sh
        ./gcp_wif_setup.sh --project YOUR_PROJECT --aws-account A13E_AWS_ACCOUNT
    """
    return _read_template("gcp_wif_setup.sh")


@router.get("/templates/gcp/wif-setup", response_class=PlainTextResponse)
async def get_gcp_wif_setup_script() -> str:
    """Download GCP Workload Identity Federation setup script (alias for setup-script)."""
    return _read_template("gcp_wif_setup.sh")


@router.get("/templates/azure/wif-setup", response_class=PlainTextResponse)
async def get_azure_wif_setup_script() -> str:
    """Download Azure Workload Identity Federation setup script.

    Uses WIF for keyless authentication from AWS to Azure.
    No client secrets required.

    Usage:
        chmod +x azure_wif_setup.sh
        ./azure_wif_setup.sh --subscription YOUR_SUBSCRIPTION_ID
    """
    return _read_template("azure_wif_setup.sh")


@router.get("/templates/entra/wif-setup", response_class=PlainTextResponse)
async def get_entra_wif_setup_script() -> str:
    """Download Microsoft Entra ID WIF setup script (alias for Azure endpoint).

    Azure Cloud Shell blocks outbound requests to URLs containing 'azure',
    so this alias uses 'entra' (Microsoft Entra ID) instead.
    """
    return _read_template("azure_wif_setup.sh")


# === Helper Functions ===


def _credential_to_response(credential: CloudCredential) -> CredentialResponse:
    """Convert credential model to response."""
    return CredentialResponse(
        id=credential.id,
        cloud_account_id=credential.cloud_account_id,
        credential_type=credential.credential_type.value,
        status=credential.status.value,
        status_message=credential.status_message,
        last_validated_at=(
            credential.last_validated_at.isoformat()
            if credential.last_validated_at
            else None
        ),
        granted_permissions=credential.granted_permissions,
        missing_permissions=credential.missing_permissions,
        aws_role_arn=credential.aws_role_arn,
        aws_external_id=credential.aws_external_id,
        gcp_project_id=credential.gcp_project_id,
        gcp_service_account_email=credential.gcp_service_account_email,
    )
