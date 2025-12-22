"""Authentication schemas for request/response validation."""

import re
from datetime import datetime
from typing import Optional, List
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict


# Password validation
PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$"
)


class LoginRequest(BaseModel):
    """Login request."""

    email: EmailStr
    password: str
    remember_me: bool = False


class LoginResponse(BaseModel):
    """Login response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "UserResponse"
    organization: Optional["OrganizationResponse"] = None
    requires_mfa: bool = False
    mfa_token: Optional[str] = None  # Partial token for MFA flow


class MFAVerifyRequest(BaseModel):
    """MFA verification request."""

    mfa_token: str
    code: str


class RefreshRequest(BaseModel):
    """Token refresh request."""

    refresh_token: str


class RefreshResponse(BaseModel):
    """Token refresh response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class CookieRefreshResponse(BaseModel):
    """Token refresh response for cookie-based auth (no refresh token in body)."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    csrf_token: str  # New CSRF token for double-submit pattern


class SignupRequest(BaseModel):
    """Signup request."""

    email: EmailStr
    password: str = Field(..., min_length=12)
    full_name: str = Field(..., min_length=2, max_length=255)
    organization_name: str = Field(..., min_length=2, max_length=255)
    terms_accepted: bool = True

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain a lowercase letter")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain an uppercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain a number")
        if not re.search(r"[@$!%*?&]", v):
            raise ValueError("Password must contain a special character (@$!%*?&)")
        return v


class SignupResponse(BaseModel):
    """Signup response."""

    user: "UserResponse"
    organization: "OrganizationResponse"
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class ForgotPasswordRequest(BaseModel):
    """Forgot password request."""

    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """Reset password request."""

    token: str
    password: str = Field(..., min_length=12)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain a lowercase letter")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain an uppercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain a number")
        if not re.search(r"[@$!%*?&]", v):
            raise ValueError("Password must contain a special character (@$!%*?&)")
        return v


class ChangePasswordRequest(BaseModel):
    """Change password request."""

    current_password: str
    new_password: str = Field(..., min_length=12)

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain a lowercase letter")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain an uppercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain a number")
        if not re.search(r"[@$!%*?&]", v):
            raise ValueError("Password must contain a special character (@$!%*?&)")
        return v


class MFASetupRequest(BaseModel):
    """MFA setup verification request."""

    code: str = Field(..., min_length=6, max_length=6)


class MFASetupResponse(BaseModel):
    """MFA setup response."""

    secret: str
    provisioning_uri: str
    qr_code_base64: Optional[str] = None


class MFABackupCodesResponse(BaseModel):
    """MFA backup codes response."""

    backup_codes: List[str]


class UserResponse(BaseModel):
    """User response."""

    id: UUID
    email: str
    full_name: str
    avatar_url: Optional[str] = None
    timezone: str
    email_verified: bool
    mfa_enabled: bool
    created_at: datetime
    role: Optional[str] = (
        None  # User's role in current org context (populated at runtime)
    )

    model_config = ConfigDict(from_attributes=True)


class UserUpdateRequest(BaseModel):
    """User profile update request."""

    full_name: Optional[str] = Field(None, min_length=2, max_length=255)
    timezone: Optional[str] = None
    avatar_url: Optional[str] = None


class OrganizationResponse(BaseModel):
    """Organization response."""

    id: UUID
    name: str
    slug: str
    logo_url: Optional[str] = None
    plan: str
    require_mfa: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrganizationCreateRequest(BaseModel):
    """Organization creation request."""

    name: str = Field(..., min_length=2, max_length=255)
    slug: str = Field(..., min_length=2, max_length=100, pattern=r"^[a-z0-9-]+$")


class OrganizationMemberResponse(BaseModel):
    """Organization member response."""

    id: UUID
    user_id: Optional[UUID] = None
    email: str
    full_name: Optional[str] = None
    role: str
    status: str
    joined_at: Optional[datetime] = None
    created_at: datetime
    avatar_url: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class InviteMemberRequest(BaseModel):
    """Invite member request."""

    email: EmailStr
    role: str = Field(default="member", pattern=r"^(admin|member|viewer)$")
    cloud_account_ids: Optional[List[UUID]] = None
    message: Optional[str] = None


class AcceptInviteRequest(BaseModel):
    """Accept invite request."""

    token: str
    full_name: str = Field(..., min_length=2, max_length=255)
    password: str = Field(..., min_length=12)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain a lowercase letter")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain an uppercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain a number")
        if not re.search(r"[@$!%*?&]", v):
            raise ValueError("Password must contain a special character (@$!%*?&)")
        return v


class UpdateMemberRoleRequest(BaseModel):
    """Update member role request."""

    role: str = Field(..., pattern=r"^(admin|member|viewer)$")
    cloud_account_ids: Optional[List[UUID]] = None


class SessionResponse(BaseModel):
    """Session response."""

    id: UUID
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None
    is_current: bool = False
    last_activity_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SwitchOrganizationRequest(BaseModel):
    """Switch organization request."""

    organization_id: UUID


class SwitchOrganizationResponse(BaseModel):
    """Switch organization response."""

    access_token: str
    organization: OrganizationResponse


# Update forward references
LoginResponse.model_rebuild()
SignupResponse.model_rebuild()
