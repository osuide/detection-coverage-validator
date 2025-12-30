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
from app.core.security import AuthContext, require_role, require_scope
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
    PERMISSIONS_NOT_REQUESTED,
)
from app.services.aws_credential_service import aws_credential_service
from app.services.gcp_credential_service import gcp_credential_service
from app.services.gcp_wif_service import gcp_wif_service, GCPWIFError

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
    provider_id: str = Field(default="aws", description="WIF provider ID")
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
                "Option A - Automated Setup:",
                "  1. Download the WIF setup script from /api/v1/credentials/templates/gcp/wif-setup",
                f"  2. Run: ./gcp_wif_setup.sh --project {account.account_id} --aws-account {a13e_account_id}",
                "  3. Copy the output values and return here to complete setup",
                "",
                "Option B - Manual Setup:",
                "  1. Go to GCP IAM Console → Workload Identity Federation",
                "  2. Create a new pool named 'a13e-pool'",
                "  3. Add an AWS provider with A13E's account ID",
                "  4. Create service account 'a13e-scanner' with read-only security permissions",
                "  5. Grant the WIF pool permission to impersonate the service account",
                "  6. Return here with the service account email",
                "",
                "NOTE: Service account keys are NOT recommended for security reasons.",
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
        ip_address=request.client.host if request.client else None,
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
        ip_address=request.client.host if request.client else None,
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
        ip_address=request.client.host if request.client else None,
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

    # Validate based on provider
    if credential.credential_type == CredentialType.AWS_IAM_ROLE:
        validation = await aws_credential_service.validate_credentials(credential)
    elif credential.credential_type in [
        CredentialType.GCP_WORKLOAD_IDENTITY,
        CredentialType.GCP_SERVICE_ACCOUNT_KEY,
    ]:
        validation = await gcp_credential_service.validate_credentials(credential)
    else:
        raise HTTPException(status_code=400, detail="Unknown credential type")

    # Update credential status
    from datetime import datetime, timezone

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
        ip_address=request.client.host if request.client else None,
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
    result = await db.execute(
        select(CloudCredential).where(
            CloudCredential.cloud_account_id == cloud_account_id,
            CloudCredential.organization_id == auth.organization_id,
        )
    )
    credential = result.scalar_one_or_none()
    if not credential:
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
        ip_address=request.client.host if request.client else None,
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
async def get_aws_cloudformation_template() -> dict:
    """Download AWS CloudFormation template."""
    return _read_template("aws_cloudformation.yaml")


@router.get("/templates/aws/terraform", response_class=PlainTextResponse)
async def get_aws_terraform_template() -> dict:
    """Download AWS Terraform module."""
    return _read_template("terraform/aws/main.tf")


@router.get("/templates/gcp/terraform", response_class=PlainTextResponse)
async def get_gcp_terraform_template() -> dict:
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
