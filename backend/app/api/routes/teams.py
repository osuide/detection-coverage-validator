"""Team/Organization member management API endpoints."""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import structlog
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
    BackgroundTasks,
)
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import (
    AuthContext,
    get_auth_context,
    get_client_ip,
    require_feature,
    require_role,
    require_scope,
)
from app.models.user import (
    OrganizationMember,
    UserRole,
    MembershipStatus,
    AuditLog,
    AuditLogAction,
)
from app.services.auth_service import AuthService
from app.models.user import User
from app.api.routes.auth import get_current_user

logger = structlog.get_logger()
settings = get_settings()
router = APIRouter()


# Request/Response schemas
class MemberResponse(BaseModel):
    """Organization member response."""

    id: UUID
    user_id: UUID
    email: str
    full_name: str
    avatar_url: Optional[str] = None
    role: UserRole
    status: MembershipStatus
    joined_at: datetime

    model_config = ConfigDict(from_attributes=True)


class InviteRequest(BaseModel):
    """Invite member request."""

    email: EmailStr
    role: UserRole = UserRole.MEMBER
    message: Optional[str] = Field(None, max_length=500)


class InviteResponse(BaseModel):
    """Invite response."""

    id: UUID
    email: str
    role: UserRole
    status: MembershipStatus
    invited_at: datetime
    expires_at: datetime


class PendingInviteResponse(BaseModel):
    """Pending invite response."""

    id: UUID
    email: str
    role: UserRole
    invited_at: datetime
    expires_at: datetime
    invited_by_name: str


class UpdateMemberRoleRequest(BaseModel):
    """Update member role request."""

    role: UserRole


class AcceptInviteRequest(BaseModel):
    """Accept invite request."""

    invite_token: str


# Helper functions
async def get_member_count(db: AsyncSession, org_id: UUID) -> int:
    """Get active member count for an organization."""
    result = await db.execute(
        select(func.count(OrganizationMember.id)).where(
            and_(
                OrganizationMember.organization_id == org_id,
                OrganizationMember.status == MembershipStatus.ACTIVE,
            )
        )
    )
    return result.scalar() or 0


async def get_pending_invite_count(db: AsyncSession, org_id: UUID) -> int:
    """Get pending invite count for an organization."""
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(func.count(OrganizationMember.id)).where(
            and_(
                OrganizationMember.organization_id == org_id,
                OrganizationMember.status == MembershipStatus.PENDING,
                OrganizationMember.invite_expires_at > now,
            )
        )
    )
    return result.scalar() or 0


async def log_team_action(
    db: AsyncSession,
    user_id: UUID,
    org_id: UUID,
    action: AuditLogAction,
    details: dict,
    ip_address: Optional[str] = None,
) -> None:
    """Log a team management action."""
    log = AuditLog(
        user_id=user_id,
        organization_id=org_id,
        action=action,
        details=details,
        ip_address=ip_address,
    )
    db.add(log)


@router.get(
    "/members",
    response_model=list[MemberResponse],
    dependencies=[Depends(require_scope("read:teams"))],
)
async def list_members(
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List all members of the current organization.

    API keys require 'read:teams' scope.
    """
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    result = await db.execute(
        select(OrganizationMember)
        .options(selectinload(OrganizationMember.user))
        .where(
            and_(
                OrganizationMember.organization_id == auth.organization_id,
                OrganizationMember.status == MembershipStatus.ACTIVE,
            )
        )
        .order_by(OrganizationMember.role.asc(), OrganizationMember.joined_at.asc())
    )
    members = result.scalars().all()

    return [
        MemberResponse(
            id=m.id,
            user_id=m.user_id,
            email=m.user.email,
            full_name=m.user.full_name,
            avatar_url=m.user.avatar_url,
            role=m.role,
            status=m.status,
            joined_at=m.joined_at,
        )
        for m in members
    ]


@router.get("/invites", response_model=list[PendingInviteResponse])
async def list_pending_invites(
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> list[PendingInviteResponse]:
    """List pending invites for the current organization.

    Note: FREE tier users will see an empty list as they cannot create invites.
    """
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(OrganizationMember)
        .options(selectinload(OrganizationMember.invited_by_user))
        .where(
            and_(
                OrganizationMember.organization_id == auth.organization_id,
                OrganizationMember.status == MembershipStatus.PENDING,
                OrganizationMember.invite_expires_at > now,
            )
        )
        .order_by(OrganizationMember.invited_at.desc())
    )
    invites = result.scalars().all()

    return [
        PendingInviteResponse(
            id=inv.id,
            email=inv.invited_email,
            role=inv.role,
            invited_at=inv.invited_at,
            expires_at=inv.invite_expires_at,
            invited_by_name=(
                inv.invited_by_user.full_name if inv.invited_by_user else "Unknown"
            ),
        )
        for inv in invites
    ]


@router.post(
    "/invites",
    response_model=InviteResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_feature("team_invites"))],
)
async def invite_member(
    request: Request,
    body: InviteRequest,
    background_tasks: BackgroundTasks,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Invite a new member to the organization.

    Requires team_invites feature (Individual tier or higher).
    Only admins and owners can invite new members.
    Owners cannot be invited directly - they must be promoted from admin.
    """
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    # Cannot invite as owner
    if body.role == UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot invite as owner. Promote an existing admin instead.",
        )

    # Check team member limit
    from app.models.billing import Subscription

    sub_result = await db.execute(
        select(Subscription).where(Subscription.organization_id == auth.organization_id)
    )
    subscription = sub_result.scalar_one_or_none()

    if subscription:
        max_members = subscription.get_tier_limit("max_team_members")
        if max_members is not None:  # None means unlimited (Enterprise)
            current_count = await get_member_count(db, auth.organization_id)
            pending_count = await get_pending_invite_count(db, auth.organization_id)

            if current_count + pending_count >= max_members:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"Team member limit ({max_members}) reached. "
                        "Upgrade to Pro for more team members."
                    ),
                )

    # Check if already a member or has pending invite
    existing_member = await db.execute(
        select(OrganizationMember)
        .options(selectinload(OrganizationMember.user))
        .where(
            and_(
                OrganizationMember.organization_id == auth.organization_id,
                OrganizationMember.status.in_(
                    [MembershipStatus.ACTIVE, MembershipStatus.PENDING]
                ),
            )
        )
    )
    existing = existing_member.scalars().all()

    # M9: Use generic message to prevent email enumeration
    for m in existing:
        if m.user and m.user.email == body.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to send invite to this email address",
            )
        if m.invited_email == body.email and m.status == MembershipStatus.PENDING:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unable to send invite to this email address",
            )

    # Check if user exists
    auth_service = AuthService(db)
    existing_user = await auth_service.get_user_by_email(body.email)

    # Create invite
    import secrets

    invite_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    invite = OrganizationMember(
        organization_id=auth.organization_id,
        user_id=existing_user.id if existing_user else None,
        invited_email=body.email,
        role=body.role,
        status=MembershipStatus.PENDING,
        invite_token=auth_service.hash_password(invite_token),  # Hash token
        invite_expires_at=expires_at,
        invited_at=datetime.now(timezone.utc),
        invited_by=auth.user.id,
    )
    db.add(invite)
    await db.flush()

    # Log the action
    await log_team_action(
        db=db,
        user_id=auth.user.id,
        org_id=auth.organization_id,
        action=AuditLogAction.MEMBER_INVITED,
        details={
            "invited_email": body.email,
            "role": body.role.value,
            "message": body.message,
        },
        ip_address=get_client_ip(request),
    )

    await db.commit()

    # Send invite email in background
    from app.services.email_service import get_email_service

    def send_invite_email_task() -> None:
        email_service = get_email_service()
        email_service.send_team_invite_email(
            to_email=body.email,
            invite_token=invite_token,
            org_name=auth.organization.name,
            role=body.role.value,
            message=body.message,
            inviter_name=auth.user.full_name,
        )

    background_tasks.add_task(send_invite_email_task)

    logger.info(
        "invite_created",
        email=body.email,
        org_id=str(auth.organization_id),
    )

    return InviteResponse(
        id=invite.id,
        email=body.email,
        role=body.role,
        status=MembershipStatus.PENDING,
        invited_at=invite.invited_at,
        expires_at=expires_at,
    )


@router.delete(
    "/invites/{invite_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_feature("team_invites"))],
)
async def cancel_invite(
    request: Request,
    invite_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Cancel a pending invite.

    Requires team_invites feature (Individual tier or higher).
    """
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    result = await db.execute(
        select(OrganizationMember).where(
            and_(
                OrganizationMember.id == invite_id,
                OrganizationMember.organization_id == auth.organization_id,
                OrganizationMember.status == MembershipStatus.PENDING,
            )
        )
    )
    invite = result.scalar_one_or_none()

    if not invite:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invite not found",
        )

    # Log the action
    await log_team_action(
        db=db,
        user_id=auth.user.id,
        org_id=auth.organization_id,
        action=AuditLogAction.MEMBER_REMOVED,
        details={
            "action": "invite_cancelled",
            "invited_email": invite.invited_email,
        },
        ip_address=get_client_ip(request),
    )

    await db.delete(invite)
    await db.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/invites/accept", response_model=MemberResponse)
async def accept_invite(
    request: Request,
    body: AcceptInviteRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MemberResponse:
    """Accept an organization invite.

    This endpoint requires user authentication (not API keys) because
    invites are tied to specific user email addresses.
    """
    auth_service = AuthService(db)
    now = datetime.now(timezone.utc)

    # Find pending invites for this user's email
    result = await db.execute(
        select(OrganizationMember)
        .options(selectinload(OrganizationMember.organization))
        .where(
            and_(
                OrganizationMember.invited_email == current_user.email,
                OrganizationMember.status == MembershipStatus.PENDING,
                OrganizationMember.invite_expires_at > now,
            )
        )
    )
    pending_invites = result.scalars().all()

    # Find the matching invite by verifying token
    invite = None
    for inv in pending_invites:
        if auth_service.verify_password(body.invite_token, inv.invite_token):
            invite = inv
            break

    if not invite:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired invite token",
        )

    # H5: Additional validation - if invite has a user_id set, verify it matches
    if invite.user_id and invite.user_id != current_user.id:
        logger.warning(
            "invite_user_mismatch",
            invite_user_id=str(invite.user_id),
            current_user_id=str(current_user.id),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This invite is not for your account",
        )

    # Accept the invite
    invite.user_id = current_user.id
    invite.status = MembershipStatus.ACTIVE
    invite.joined_at = now
    invite.invite_token = None
    invite.invite_expires_at = None

    # Log the action
    await log_team_action(
        db=db,
        user_id=current_user.id,
        org_id=invite.organization_id,
        action=AuditLogAction.MEMBER_JOINED,
        details={
            "role": invite.role.value,
            "organization_name": invite.organization.name,
        },
        ip_address=get_client_ip(request),
    )

    await db.commit()

    return MemberResponse(
        id=invite.id,
        user_id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        avatar_url=current_user.avatar_url,
        role=invite.role,
        status=MembershipStatus.ACTIVE,
        joined_at=invite.joined_at,
    )


@router.patch("/members/{member_id}/role", response_model=MemberResponse)
async def update_member_role(
    request: Request,
    member_id: UUID,
    body: UpdateMemberRoleRequest,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> MemberResponse:
    """
    Update a member's role.

    - Admins can change member/viewer roles
    - Only owners can promote to admin or demote admins
    - Only owners can transfer ownership
    """
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    result = await db.execute(
        select(OrganizationMember)
        .options(selectinload(OrganizationMember.user))
        .where(
            and_(
                OrganizationMember.id == member_id,
                OrganizationMember.organization_id == auth.organization_id,
                OrganizationMember.status == MembershipStatus.ACTIVE,
            )
        )
    )
    member = result.scalar_one_or_none()

    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found",
        )

    # Cannot modify your own role
    if member.user_id == auth.user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot modify your own role",
        )

    # Check permissions for role changes
    current_role = auth.membership.role if auth.membership else UserRole.MEMBER

    # Only owner can change admin roles or transfer ownership
    old_role = member.role  # Capture before any changes

    if body.role == UserRole.OWNER:
        if current_role != UserRole.OWNER:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only owners can transfer ownership",
            )
        # Transfer ownership atomically with row-level locking to prevent
        # race conditions. Lock both membership records for consistent state.
        await db.execute(
            select(OrganizationMember)
            .where(OrganizationMember.id.in_([member.id, auth.membership.id]))
            .with_for_update()
        )
        # Now safely transfer ownership
        auth.membership.role = UserRole.ADMIN
        member.role = UserRole.OWNER

    elif body.role == UserRole.ADMIN or member.role == UserRole.ADMIN:
        if current_role != UserRole.OWNER:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only owners can promote to or demote from admin",
            )
        member.role = body.role

    else:
        # Regular role change (member/viewer)
        member.role = body.role

    # Log the action
    await log_team_action(
        db=db,
        user_id=auth.user.id,
        org_id=auth.organization_id,
        action=AuditLogAction.MEMBER_ROLE_CHANGED,
        details={
            "target_user_id": str(member.user_id),
            "old_role": old_role.value,
            "new_role": body.role.value,
        },
        ip_address=get_client_ip(request),
    )

    await db.commit()

    return MemberResponse(
        id=member.id,
        user_id=member.user_id,
        email=member.user.email,
        full_name=member.user.full_name,
        avatar_url=member.user.avatar_url,
        role=member.role,
        status=member.status,
        joined_at=member.joined_at,
    )


@router.delete("/members/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    request: Request,
    member_id: UUID,
    auth: AuthContext = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Remove a member from the organization.

    - Admins can remove members and viewers
    - Only owners can remove admins
    - Owners cannot be removed (must transfer ownership first)
    """
    if not auth.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    result = await db.execute(
        select(OrganizationMember)
        .options(selectinload(OrganizationMember.user))
        .where(
            and_(
                OrganizationMember.id == member_id,
                OrganizationMember.organization_id == auth.organization_id,
                OrganizationMember.status == MembershipStatus.ACTIVE,
            )
        )
    )
    member = result.scalar_one_or_none()

    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found",
        )

    # Cannot remove yourself
    if member.user_id == auth.user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove yourself. Use leave endpoint instead.",
        )

    # Cannot remove owner
    if member.role == UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove owner. Transfer ownership first.",
        )

    # Only owner can remove admins
    current_role = auth.membership.role if auth.membership else UserRole.MEMBER
    if member.role == UserRole.ADMIN and current_role != UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only owners can remove admins",
        )

    # Log the action
    await log_team_action(
        db=db,
        user_id=auth.user.id,
        org_id=auth.organization_id,
        action=AuditLogAction.MEMBER_REMOVED,
        details={
            "removed_user_id": str(member.user_id),
            "removed_email": member.user.email if member.user else member.invited_email,
            "role": member.role.value,
        },
        ip_address=get_client_ip(request),
    )

    # Soft delete - mark as removed
    member.status = MembershipStatus.REMOVED

    await db.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/leave", status_code=status.HTTP_204_NO_CONTENT)
async def leave_organization(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Leave the current organization.

    Owners cannot leave - must transfer ownership first.
    """
    if not auth.organization_id or not auth.membership:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )

    if auth.membership.role == UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Owners cannot leave. Transfer ownership first.",
        )

    # Log the action
    await log_team_action(
        db=db,
        user_id=auth.user.id,
        org_id=auth.organization_id,
        action=AuditLogAction.MEMBER_REMOVED,
        details={
            "action": "self_leave",
            "role": auth.membership.role.value,
        },
        ip_address=get_client_ip(request),
    )

    # Mark as removed
    auth.membership.status = MembershipStatus.REMOVED

    await db.commit()

    return Response(status_code=status.HTTP_204_NO_CONTENT)
