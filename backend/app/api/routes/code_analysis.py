"""Code Analysis API endpoints.

Premium feature for paying subscribers that enables deeper analysis
of Lambda functions and IaC templates for more accurate MITRE mappings.

Requires:
1. Subscriber or Enterprise tier
2. Explicit user consent
3. Required IAM permissions
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import AuthContext, get_auth_context, require_scope
from app.models.cloud_account import CloudAccount
from app.models.code_analysis import (
    CodeAnalysisConsent,
    CodeAnalysisScope,
    CODE_ANALYSIS_DISCLOSURE,
    CODE_ANALYSIS_IAM_PERMISSIONS,
)
from app.models.billing import Subscription, AccountTier

router = APIRouter()


# === Request/Response Schemas ===


class ConsentRequest(BaseModel):
    """Request to give consent for code analysis."""

    cloud_account_id: UUID
    scope: CodeAnalysisScope = CodeAnalysisScope.ALL
    acknowledged_risks: bool
    acknowledged_data_handling: bool


class ConsentResponse(BaseModel):
    """Response with consent status."""

    id: UUID
    cloud_account_id: UUID
    consent_given: bool
    scope: str
    acknowledged_risks: bool
    acknowledged_data_handling: bool
    consent_revoked: bool
    is_active: bool


class DisclosureResponse(BaseModel):
    """Response with feature disclosure information."""

    title: str
    summary: str
    benefits: list[str]
    what_we_access: list[str]
    what_we_dont_do: list[str]
    data_handling: dict
    risks: list[str]
    can_revoke: bool
    revoke_effect: str
    iam_permissions: dict


class PermissionCheckResponse(BaseModel):
    """Response from IAM permission check."""

    has_required_permissions: bool
    missing_permissions: list[str]
    warnings: list[str]
    policy_recommendation: dict


class FeatureStatusResponse(BaseModel):
    """Overall status of code analysis feature for an account."""

    feature_available: bool  # Tier allows it
    consent_given: bool
    consent_active: bool
    permissions_checked: bool
    has_permissions: bool
    missing_permissions: list[str]
    ready_to_use: bool
    blocking_reasons: list[str]


# === Endpoints ===


@router.get("/disclosure", response_model=DisclosureResponse)
async def get_disclosure() -> DisclosureResponse:
    """Get the disclosure information for code analysis feature.

    This endpoint is public and returns all the information users need
    to make an informed decision about enabling code analysis.
    """
    return DisclosureResponse(
        **CODE_ANALYSIS_DISCLOSURE,
        iam_permissions=CODE_ANALYSIS_IAM_PERMISSIONS,
    )


@router.get(
    "/status/{cloud_account_id}",
    response_model=FeatureStatusResponse,
    dependencies=[Depends(require_scope("read:code_analysis"))],
)
async def get_feature_status(
    cloud_account_id: UUID,
    auth_ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get the overall status of code analysis feature for an account.

    Returns whether the feature is available, consent status, and
    any blocking reasons that prevent use.
    """
    org = auth_ctx.organization

    # Check subscription tier
    result = await db.execute(
        select(Subscription).where(Subscription.organization_id == org.id)
    )
    subscription = result.scalar_one_or_none()

    feature_available = False
    if subscription:
        feature_available = subscription.tier in [
            AccountTier.SUBSCRIBER,
            AccountTier.ENTERPRISE,
        ]

    # Check consent - filter by organization_id for proper tenant isolation
    result = await db.execute(
        select(CodeAnalysisConsent).where(
            CodeAnalysisConsent.cloud_account_id == cloud_account_id,
            CodeAnalysisConsent.organization_id == org.id,
        )
    )
    consent = result.scalar_one_or_none()

    consent_given = consent.consent_given if consent else False
    consent_active = consent.is_active if consent else False

    # Build blocking reasons
    blocking_reasons = []
    if not feature_available:
        blocking_reasons.append(
            "Upgrade to Subscriber or Enterprise tier to access code analysis"
        )
    if not consent_given:
        blocking_reasons.append(
            "Code analysis requires explicit consent - review disclosure and enable"
        )
    if consent and consent.consent_revoked:
        blocking_reasons.append("Consent was revoked - re-enable to use code analysis")

    ready_to_use = feature_available and consent_active

    return FeatureStatusResponse(
        feature_available=feature_available,
        consent_given=consent_given,
        consent_active=consent_active,
        permissions_checked=False,  # Would need AWS credentials to check
        has_permissions=False,
        missing_permissions=[],
        ready_to_use=ready_to_use,
        blocking_reasons=blocking_reasons,
    )


@router.post(
    "/consent",
    response_model=ConsentResponse,
    dependencies=[Depends(require_scope("write:code_analysis"))],
)
async def give_consent(
    request: ConsentRequest,
    auth_ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Give consent for code analysis on a cloud account.

    Requires:
    - Subscriber or Enterprise tier
    - Acknowledgment of risks
    - Acknowledgment of data handling

    The user must review the disclosure endpoint first and explicitly
    acknowledge both risks and data handling practices.
    """
    org = auth_ctx.organization
    current_user = auth_ctx.user

    # Verify tier
    result = await db.execute(
        select(Subscription).where(Subscription.organization_id == org.id)
    )
    subscription = result.scalar_one_or_none()

    if not subscription or subscription.tier not in [
        AccountTier.SUBSCRIBER,
        AccountTier.ENTERPRISE,
    ]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Code analysis requires Subscriber or Enterprise tier. Please upgrade your subscription.",
        )

    # Verify account belongs to org
    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == request.cloud_account_id,
            CloudAccount.organization_id == org.id,
        )
    )
    account = result.scalar_one_or_none()

    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Cloud account not found"
        )

    # Require explicit acknowledgments
    if not request.acknowledged_risks:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You must acknowledge the risks before enabling code analysis. Please review the disclosure.",
        )

    if not request.acknowledged_data_handling:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You must acknowledge the data handling practices before enabling code analysis. Please review the disclosure.",
        )

    # Check for existing consent
    result = await db.execute(
        select(CodeAnalysisConsent).where(
            CodeAnalysisConsent.cloud_account_id == request.cloud_account_id
        )
    )
    consent = result.scalar_one_or_none()

    from datetime import datetime, timezone

    if consent:
        # Update existing consent
        consent.consent_given = True
        consent.consent_given_by = current_user.id
        consent.consent_given_at = datetime.now(timezone.utc)
        consent.scope = request.scope
        consent.acknowledged_risks = request.acknowledged_risks
        consent.acknowledged_data_handling = request.acknowledged_data_handling
        consent.consent_revoked = False
        consent.consent_revoked_by = None
        consent.consent_revoked_at = None
        consent.revocation_reason = None
    else:
        # Create new consent
        consent = CodeAnalysisConsent(
            organization_id=org.id,
            cloud_account_id=request.cloud_account_id,
            consent_given=True,
            consent_given_by=current_user.id,
            consent_given_at=datetime.now(timezone.utc),
            scope=request.scope,
            acknowledged_risks=request.acknowledged_risks,
            acknowledged_data_handling=request.acknowledged_data_handling,
        )
        db.add(consent)

    await db.commit()
    await db.refresh(consent)

    return ConsentResponse(
        id=consent.id,
        cloud_account_id=consent.cloud_account_id,
        consent_given=consent.consent_given,
        scope=consent.scope.value,
        acknowledged_risks=consent.acknowledged_risks,
        acknowledged_data_handling=consent.acknowledged_data_handling,
        consent_revoked=consent.consent_revoked,
        is_active=consent.is_active,
    )


@router.delete(
    "/consent/{cloud_account_id}",
    dependencies=[Depends(require_scope("write:code_analysis"))],
)
async def revoke_consent(
    cloud_account_id: UUID,
    reason: Optional[str] = None,
    auth_ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Revoke consent for code analysis.

    Users can revoke consent at any time. This will:
    - Stop all future code analysis for this account
    - Mark any existing mappings from code analysis as 'legacy'
    - NOT delete existing mappings (they remain for reference)
    """
    org = auth_ctx.organization
    current_user = auth_ctx.user

    result = await db.execute(
        select(CodeAnalysisConsent).where(
            CodeAnalysisConsent.cloud_account_id == cloud_account_id,
            CodeAnalysisConsent.organization_id == org.id,
        )
    )
    consent = result.scalar_one_or_none()

    if not consent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No consent record found for this account",
        )

    from datetime import datetime, timezone

    consent.consent_revoked = True
    consent.consent_revoked_by = current_user.id
    consent.consent_revoked_at = datetime.now(timezone.utc)
    consent.revocation_reason = reason

    await db.commit()

    return {
        "message": "Consent revoked successfully",
        "account_id": str(cloud_account_id),
        "revoked_at": consent.consent_revoked_at.isoformat(),
        "note": "Future scans will use metadata-only analysis. Existing mappings are preserved.",
    }


@router.get(
    "/consent/{cloud_account_id}",
    response_model=ConsentResponse,
    dependencies=[Depends(require_scope("read:code_analysis"))],
)
async def get_consent(
    cloud_account_id: UUID,
    auth_ctx: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Get current consent status for a cloud account."""
    org = auth_ctx.organization

    result = await db.execute(
        select(CodeAnalysisConsent).where(
            CodeAnalysisConsent.cloud_account_id == cloud_account_id,
            CodeAnalysisConsent.organization_id == org.id,
        )
    )
    consent = result.scalar_one_or_none()

    if not consent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No consent record found. Code analysis has not been enabled for this account.",
        )

    return ConsentResponse(
        id=consent.id,
        cloud_account_id=consent.cloud_account_id,
        consent_given=consent.consent_given,
        scope=consent.scope.value,
        acknowledged_risks=consent.acknowledged_risks,
        acknowledged_data_handling=consent.acknowledged_data_handling,
        consent_revoked=consent.consent_revoked,
        is_active=consent.is_active,
    )


@router.get("/iam-policy")
async def get_iam_policy() -> dict:
    """Get the IAM policy required for code analysis.

    Returns a ready-to-use IAM policy document that users can
    attach to their cross-account role to enable code analysis.
    """
    from app.parsers.lambda_code_parser import LambdaCodeParser
    from app.parsers.cloudformation_parser import CloudFormationParser

    lambda_reqs = LambdaCodeParser(None).get_permission_requirements()
    cfn_reqs = CloudFormationParser(None).get_permission_requirements()

    # Combine all permissions
    all_permissions = set()
    all_permissions.update(lambda_reqs["required_permissions"])
    all_permissions.update(cfn_reqs["required_permissions"])

    combined_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "A13ECodeAnalysis",
                "Effect": "Allow",
                "Action": sorted(list(all_permissions)),
                "Resource": "*",
            }
        ],
    }

    return {
        "policy_name": "A13E-CodeAnalysis-Policy",
        "policy_document": combined_policy,
        "description": (
            "This policy grants A13E permission to download and analyze "
            "Lambda function code and CloudFormation templates for enhanced "
            "MITRE ATT&CK mapping accuracy."
        ),
        "components": {
            "lambda_analysis": lambda_reqs,
            "cloudformation_analysis": cfn_reqs,
        },
        "important_notes": [
            "Code is analyzed in-memory and never stored",
            "You can revoke consent at any time to stop code analysis",
            "This policy is OPTIONAL - basic scanning works without it",
        ],
    }
