# Authentication & Authorization Flow

## Overview

This document describes how AuthN/AuthZ works in the Detection Coverage Validator.

## Key Concepts

### User vs Role
- **User**: The authenticated person (stored in `users` table)
- **Role**: User's permission level within an organization (stored in `organization_members` table)
- A user can be in multiple organizations with different roles

### Role Hierarchy
```
OWNER > ADMIN > MEMBER > VIEWER
```

| Role | Permissions |
|------|-------------|
| OWNER | Full org control, billing, delete org |
| ADMIN | Manage members, most settings |
| MEMBER | Full access to assigned accounts |
| VIEWER | Read-only access to assigned accounts |

## Authentication Flow

### Login (Password)
```
POST /api/v1/auth/login
→ Validates credentials
→ Gets user's organizations
→ Gets membership in first org
→ Extracts role from membership
→ Returns LoginResponse with user.role populated
```

### Login (MFA)
```
POST /api/v1/auth/login/mfa
→ Validates MFA code
→ Gets user's organizations
→ Gets membership in first org
→ Extracts role from membership
→ Returns LoginResponse with user.role populated
```

### Signup
```
POST /api/v1/auth/signup
→ Creates user
→ Creates organization (user becomes OWNER)
→ Returns SignupResponse with user.role = "owner"
```

### Get Current User
```
GET /api/v1/auth/me
→ Uses AuthContext dependency
→ AuthContext has user, organization, and membership
→ Extracts role from membership
→ Returns UserResponse with user.role populated
```

## JWT Token Structure

```json
{
  "sub": "user-uuid",
  "org": "organization-uuid",  // Optional - current org context
  "exp": 1234567890,
  "iat": 1234567890,
  "type": "access"
}
```

**Note**: Role is NOT in the JWT. It's fetched from the database on each request.

## Authorization in Endpoints

### Using AuthContext
```python
from app.core.security import AuthContext, get_auth_context, require_role

@router.get("/protected")
async def protected_endpoint(
    auth: AuthContext = Depends(get_auth_context),
):
    # auth.user - User object
    # auth.organization - Organization object
    # auth.membership - OrganizationMember object
    # auth.role - UserRole enum (from membership)
    pass
```

### Role-Based Access
```python
from app.core.security import require_role
from app.models.user import UserRole

@router.post("/admin-only")
async def admin_only(
    auth: AuthContext = Depends(require_role(UserRole.ADMIN, UserRole.OWNER)),
):
    # Only admins and owners can access
    pass
```

### Account-Level Access
```python
@router.get("/accounts/{account_id}")
async def get_account(
    account_id: UUID,
    auth: AuthContext = Depends(get_auth_context),
):
    if not auth.can_access_account(account_id):
        raise HTTPException(403)
    # Members/viewers are restricted to allowed_account_ids
    pass
```

## Frontend Integration

### Auth Context (React)
```typescript
const { user, organization, token } = useAuth()

// user.role is populated from backend
if (user?.role === 'owner') {
  // Show owner-only features
}
```

### API Calls
All API calls include the JWT in Authorization header:
```typescript
Authorization: Bearer <jwt_token>
```

The backend extracts:
1. User ID from `sub` claim
2. Organization ID from `org` claim
3. Membership from database (contains role)

## Security Considerations

1. **Role Cached in Frontend**: Frontend stores role from login response. If role changes server-side, user must re-login.

2. **Multi-Org Users**: When user switches org, a new token is issued with the new org context.

3. **API Keys**: API keys have organization scope but no user role. They bypass user-based RBAC.

4. **Token Refresh**: Token refresh doesn't change user object - role persists until new login.

## Troubleshooting

### "user.role is undefined"
- User needs to log out and log back in
- Backend endpoint may not be populating role

### "Access denied" for owner
- Check organization_members table for correct role
- Verify JWT has correct org claim
- Verify membership status is "active"

### Role not updating after promotion
- User must log out and log back in
- Or switch organization and switch back

---

*Last Updated: 2025-12-18*
