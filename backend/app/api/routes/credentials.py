"""Cloud Credential API endpoints.

Provides secure credential management for connecting AWS and GCP accounts.
"""

import json
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
from app.core.security import AuthContext, require_role
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

logger = structlog.get_logger()
router = APIRouter()


# === Request/Response Schemas ===

class AWSCredentialCreate(BaseModel):
    """Request to create AWS credential."""
    cloud_account_id: UUID
    role_arn: str = Field(..., pattern=r'^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$')

    @field_validator('role_arn')
    @classmethod
    def validate_role_arn(cls, v: str) -> str:
        if not v.startswith('arn:aws:iam::'):
            raise ValueError('Invalid AWS role ARN format')
        return v


class GCPCredentialCreate(BaseModel):
    """Request to create GCP credential."""
    cloud_account_id: UUID
    credential_type: str = Field(..., pattern='^(gcp_workload_identity|gcp_service_account_key)$')
    service_account_email: Optional[str] = None
    service_account_key: Optional[str] = None  # JSON string

    @field_validator('service_account_key')
    @classmethod
    def validate_key(cls, v: Optional[str]) -> Optional[str]:
        if v:
            try:
                key_data = json.loads(v)
                if 'private_key' not in key_data:
                    raise ValueError('Invalid service account key format')
            except json.JSONDecodeError:
                raise ValueError('Service account key must be valid JSON')
        return v


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

@router.get("/setup/{cloud_account_id}", response_model=SetupInstructionsResponse)
async def get_setup_instructions(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
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
        external_id = existing.aws_external_id if existing else CloudCredential.generate_external_id()

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

        return SetupInstructionsResponse(
            provider="gcp",
            external_id=None,
            iam_policy=None,
            custom_role=GCP_CUSTOM_ROLE,
            required_permissions=GCP_REQUIRED_PERMISSIONS,
            not_requested=PERMISSIONS_NOT_REQUESTED["gcp"],
            cloudformation_template_url=None,
            terraform_module_url="/api/v1/credentials/templates/gcp/terraform",
            gcloud_commands=gcloud_commands,
            manual_steps=[
                "Go to GCP IAM Console → Roles → Create Role",
                "Name it 'A13E Detection Scanner' and add the permissions listed above",
                "Go to Service Accounts → Create Service Account",
                "Name it 'a13e-scanner' with description 'A13E Detection Coverage Scanner'",
                "Grant the custom role to the service account",
                "For Workload Identity: Note the service account email (e.g., a13e-scanner@PROJECT.iam.gserviceaccount.com)",
                "For SA Key: Go to Keys → Add Key → Create new key → JSON",
                "Return here with the service account email (and key file if using SA Key method)",
            ],
        )

    raise HTTPException(status_code=400, detail="Unsupported provider")


@router.post("/aws", response_model=CredentialResponse)
async def create_aws_credential(
    request: Request,
    body: AWSCredentialCreate,
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
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
    result = await db.execute(
        select(CloudCredential).where(
            CloudCredential.cloud_account_id == body.cloud_account_id
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
        details={"action": "aws_credential_created", "role_arn": body.role_arn[:50] + "..."},
        ip_address=request.client.host if request.client else None,
        success=True,
    )
    db.add(audit_log)
    await db.commit()

    return _credential_to_response(credential)


@router.post("/gcp", response_model=CredentialResponse)
async def create_gcp_credential(
    request: Request,
    body: GCPCredentialCreate,
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
    """Create or update GCP credential."""
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
    result = await db.execute(
        select(CloudCredential).where(
            CloudCredential.cloud_account_id == body.cloud_account_id
        )
    )
    credential = result.scalar_one_or_none()

    cred_type = CredentialType(body.credential_type)

    if credential:
        credential.credential_type = cred_type
        credential.gcp_project_id = account.account_id
        credential.gcp_service_account_email = body.service_account_email
        if body.service_account_key:
            credential.set_gcp_service_account_key(body.service_account_key)
        credential.status = CredentialStatus.PENDING
    else:
        credential = CloudCredential(
            cloud_account_id=body.cloud_account_id,
            organization_id=auth.organization_id,
            credential_type=cred_type,
            gcp_project_id=account.account_id,
            gcp_service_account_email=body.service_account_email,
            status=CredentialStatus.PENDING,
            created_by=auth.user.id,
        )
        if body.service_account_key:
            credential.set_gcp_service_account_key(body.service_account_key)
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
            "type": body.credential_type,
            "service_account": body.service_account_email,
        },
        ip_address=request.client.host if request.client else None,
        success=True,
    )
    db.add(audit_log)
    await db.commit()

    return _credential_to_response(credential)


@router.post("/validate/{cloud_account_id}", response_model=ValidationResponse)
async def validate_credential(
    cloud_account_id: UUID,
    request: Request,
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
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
    credential.status = validation['status']
    credential.status_message = validation['message']
    credential.last_validated_at = datetime.now(timezone.utc)
    credential.granted_permissions = validation['granted_permissions']
    credential.missing_permissions = validation['missing_permissions']

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
            "status": validation['status'].value,
            "missing_count": len(validation['missing_permissions']),
        },
        ip_address=request.client.host if request.client else None,
        success=validation['status'] == CredentialStatus.VALID,
    )
    db.add(audit_log)
    await db.commit()

    return ValidationResponse(
        status=validation['status'].value,
        message=validation['message'],
        granted_permissions=validation['granted_permissions'],
        missing_permissions=validation['missing_permissions'],
    )


@router.get("/{cloud_account_id}", response_model=CredentialResponse)
async def get_credential(
    cloud_account_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.MEMBER, UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
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


@router.delete("/{cloud_account_id}")
async def delete_credential(
    cloud_account_id: UUID,
    request: Request,
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
    db: AsyncSession = Depends(get_db),
):
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

@router.get("/templates/aws/cloudformation", response_class=PlainTextResponse)
async def get_aws_cloudformation_template():
    """Download AWS CloudFormation template."""
    import os
    template_path = os.path.join(
        os.path.dirname(__file__),
        "../../templates/aws_cloudformation.yaml"
    )
    with open(template_path, 'r') as f:
        return f.read()


@router.get("/templates/aws/terraform", response_class=PlainTextResponse)
async def get_aws_terraform_template():
    """Download AWS Terraform module."""
    import os
    template_path = os.path.join(
        os.path.dirname(__file__),
        "../../templates/terraform/aws/main.tf"
    )
    with open(template_path, 'r') as f:
        return f.read()


@router.get("/templates/gcp/terraform", response_class=PlainTextResponse)
async def get_gcp_terraform_template():
    """Download GCP Terraform module."""
    import os
    template_path = os.path.join(
        os.path.dirname(__file__),
        "../../templates/terraform/gcp/main.tf"
    )
    with open(template_path, 'r') as f:
        return f.read()


@router.get("/templates/gcp/setup-script", response_class=PlainTextResponse)
async def get_gcp_setup_script():
    """Download GCP setup shell script."""
    import os
    template_path = os.path.join(
        os.path.dirname(__file__),
        "../../templates/gcp_setup.sh"
    )
    with open(template_path, 'r') as f:
        return f.read()


# === Helper Functions ===

def _credential_to_response(credential: CloudCredential) -> CredentialResponse:
    """Convert credential model to response."""
    return CredentialResponse(
        id=credential.id,
        cloud_account_id=credential.cloud_account_id,
        credential_type=credential.credential_type.value,
        status=credential.status.value,
        status_message=credential.status_message,
        last_validated_at=credential.last_validated_at.isoformat() if credential.last_validated_at else None,
        granted_permissions=credential.granted_permissions,
        missing_permissions=credential.missing_permissions,
        aws_role_arn=credential.aws_role_arn,
        aws_external_id=credential.aws_external_id,
        gcp_project_id=credential.gcp_project_id,
        gcp_service_account_email=credential.gcp_service_account_email,
    )
