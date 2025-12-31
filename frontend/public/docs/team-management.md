# Team Management

Manage your organisation's team members, roles, and permissions in A13E.

## TL;DR

- **Four roles**: Owner (full control), Admin (team management), Member (run scans), Viewer (read-only)
- **Invite team members** via email with role assignment
- **Role-based access control** protects sensitive operations
- **Free plan**: 1 user. Individual: 3 users. Pro: 10 users. Enterprise: Unlimited

---

## User Roles

A13E uses role-based access control (RBAC) with four roles. Each role has specific permissions.

### Owner

**Full administrative control** of the organisation.

- Manage billing and subscription
- Transfer ownership
- Delete the organisation
- All Admin, Member, and Viewer permissions

Only one Owner per organisation. Typically: CISO, security team lead, or organisation founder.

### Admin

**Team and settings management** capabilities.

- Invite and remove team members
- Change member roles (except to Owner)
- Manage organisation settings
- View audit logs
- All Member and Viewer permissions

Cannot manage billing or delete the organisation. Typically: security engineers, team managers.

### Member

**Operational access** to run scans and manage accounts.

- Add and configure cloud accounts
- Run manual scans
- View all coverage data and reports
- Export data (CSV, PDF)
- All Viewer permissions

Cannot invite users, configure scheduled scans, or access audit logs. Typically: security analysts, DevSecOps engineers.

### Viewer

**Read-only access** to dashboards and reports.

- View Dashboard, Coverage, Detections, Gaps
- View Compliance data
- Browse scan results

Cannot run scans, modify settings, or export data. Typically: executives, compliance auditors, stakeholders.

---

## Inviting Team Members

> **Who can invite**: Owner and Admin roles only

### Before You Start

- Ensure you have available seats on your subscription plan
- Know the email address and appropriate role for the new member

### How to Invite

1. Navigate to **Settings** → **Team Management**
2. Click **Invite Member**
3. Enter the invitee's **email address**
4. Select their **role**:
   - Viewer (read-only)
   - Member (can run scans)
   - Admin (can manage team)
5. Optionally add a **personal message**
6. Click **Send Invite**

### What Happens Next

1. The invitee receives an email with an invitation link
2. If they don't have an A13E account, they'll create one during acceptance
3. Once accepted, they appear in your team list
4. Their permissions take effect immediately

### Invitation Expiration

- Invitations expire after **7 days**
- You can cancel pending invitations from the Team Management page
- Expired invitations require re-sending

### Tracking Invitations

View pending invitations on the Team Management page:

- **Email**: Who was invited
- **Role**: What role they'll receive
- **Sent**: When the invitation was sent
- **Actions**: Cancel the invitation

---

## Managing Team Members

### Viewing Your Team

Navigate to **Settings** → **Team Management** to see all team members:

| Column | Description |
|--------|-------------|
| **Name** | Member's display name |
| **Email** | Member's email address |
| **Role** | Current role (Owner, Admin, Member, Viewer) |
| **Joined** | When they joined the organisation |
| **Last active** | When they last used A13E |

### Changing Roles

**Who can change roles**: Owner and Admin

**Restrictions**:
- Admins cannot promote members to Admin
- Admins cannot change other Admins or the Owner
- Only Owner can promote members to Admin

**How to change a role**:

1. Find the member in the team list
2. Click the **Actions** menu (⋮)
3. Select the new role
4. The member receives an email notification

### Removing Team Members

**Who can remove members**: Owner and Admin

**Restrictions**:
- Admins cannot remove other Admins
- Admins cannot remove the Owner
- You cannot remove yourself (Owner must transfer ownership first)

**How to remove a member**:

1. Click the **Actions** menu (⋮) on the member's row
2. Click **Remove from team**
3. Confirm the action

**What happens**:
- Member loses access immediately
- Their actions remain in audit logs
- They can be re-invited later if needed

### Transferring Ownership

> **Owner only**

If you're leaving the organisation or changing responsibilities:

1. Navigate to **Settings** → **Organisation**
2. Click **Transfer Ownership**
3. Select the new Owner (must currently be an Admin)
4. Confirm with your password
5. Complete the transfer

**Important**:
- This action cannot be undone
- Billing ownership also transfers
- You'll become an Admin after transfer

---

## Permissions Matrix

| Capability | Owner | Admin | Member | Viewer |
|------------|:-----:|:-----:|:------:|:------:|
| **Viewing** |
| View Dashboard | ✓ | ✓ | ✓ | ✓ |
| View Coverage | ✓ | ✓ | ✓ | ✓ |
| View Detections | ✓ | ✓ | ✓ | ✓ |
| View Gaps | ✓ | ✓ | ✓ | ✓ |
| View Compliance | ✓ | ✓ | ✓ | ✓ |
| **Cloud Accounts** |
| Add accounts | ✓ | ✓ | ✓ | ✗ |
| Connect credentials | ✓ | ✓ | ✓ | ✗ |
| Configure regions | ✓ | ✓ | ✓ | ✗ |
| Delete accounts | ✓ | ✓ | ✗ | ✗ |
| **Scanning** |
| Run manual scans | ✓ | ✓ | ✓ | ✗ |
| Configure schedules | ✓ | ✓ | ✗ | ✗ |
| View scan history | ✓ | ✓ | ✓ | ✓ |
| **Reporting** |
| Export CSV | ✓ | ✓ | ✓ | ✗ |
| Export PDF | ✓ | ✓ | ✓ | ✗ |
| **Team Management** |
| Invite members | ✓ | ✓* | ✗ | ✗ |
| Remove members | ✓ | ✓* | ✗ | ✗ |
| Change roles | ✓ | ✓** | ✗ | ✗ |
| **Organisation** |
| Edit settings | ✓ | ✓ | ✗ | ✗ |
| View audit logs | ✓ | ✓ | ✗ | ✗ |
| Manage billing | ✓ | ✗ | ✗ | ✗ |
| Delete organisation | ✓ | ✗ | ✗ | ✗ |
| Transfer ownership | ✓ | ✗ | ✗ | ✗ |

*Admins can only remove Members and Viewers
**Admins cannot promote to Admin or change Admin/Owner roles

---

## Team Limits by Plan

| Plan | Team Members | Notes |
|------|--------------|-------|
| **Free** | 1 | Owner only |
| **Individual** | 3 | Can invite 2 additional members |
| **Pro** | 10 | Can invite 9 additional members |
| **Enterprise** | Unlimited | No restrictions |

To add more seats, upgrade your plan in **Settings** → **Billing**.

---

## Audit Logs

> **Available to**: Owner and Admin roles

Track all significant actions in your organisation.

### Accessing Audit Logs

1. Navigate to **Settings** → **Audit Logs**
2. Filter by:
   - **Date range**: Last 24 hours, 7 days, 30 days, custom
   - **User**: Specific team member
   - **Action type**: Sign-in, team changes, scans, etc.

### What's Logged

| Category | Actions Tracked |
|----------|-----------------|
| **Authentication** | Sign-in, sign-out, MFA verification |
| **Team** | Invitations, role changes, member removal |
| **Accounts** | Added, connected, deleted |
| **Scans** | Manual scans, scheduled scans |
| **Settings** | Organisation settings changes |

### Exporting Logs

Click **Export CSV** to download audit logs for compliance documentation.

---

## Best Practices

### Role Assignment

Follow the principle of least privilege:

1. Start users with **Viewer** role
2. Promote to **Member** when they need to run scans
3. Grant **Admin** only to those managing the team
4. Keep **Owner** role with a single accountable person

### Role Selection Guide

| User Type | Recommended Role |
|-----------|------------------|
| Executives viewing reports | Viewer |
| Compliance auditors | Viewer |
| Security analysts reviewing data | Viewer or Member |
| Security engineers running scans | Member |
| Team leads managing team | Admin |
| CISO or security director | Owner or Admin |

### Security Practices

**Access Management**:
- Review team members quarterly
- Remove inactive users promptly
- Verify roles match current responsibilities
- Check audit logs regularly for anomalies

**Authentication**:
- Require MFA for Admin and Owner roles (configure in Settings → Security)
- Encourage MFA for all users
- Use SSO for Enterprise plans (centralised access control)

**Offboarding**:
When team members leave:
1. Remove them from the organisation immediately
2. Rotate any API keys they had access to
3. Review audit logs for their recent activities
4. Reassign any scheduled scans they owned

---

## Enterprise Features

### SSO Integration

> **Enterprise plan only**

Centralise authentication with your identity provider:

- **Google Workspace**: OIDC integration
- **Okta**: SAML 2.0 integration
- **Azure AD**: SAML 2.0 integration

Benefits:
- Automatic user provisioning
- Centralised access revocation
- Enforce company password policies
- MFA through your IdP

Contact support@a13e.com for SSO setup.

### Multiple Organisations

Enterprise customers can manage multiple organisations:

- Separate organisations for different business units
- Consolidated billing across organisations
- Cross-organisation reporting

---

## Common Questions

**Q: Can I have multiple Owners?**

A: No, there can only be one Owner per organisation. This ensures clear accountability for billing and administration.

**Q: What happens if the Owner leaves the company?**

A: The Owner should transfer ownership before leaving. If they're unable to, contact support@a13e.com with proof of authority to request an ownership transfer.

**Q: Can I downgrade someone from Admin to Member?**

A: Yes, the Owner can change any role. Admins can downgrade Members to Viewers but cannot change other Admin roles.

**Q: How many pending invitations can I have?**

A: There's no limit on pending invitations, but they expire after 7 days. Invitations don't count against your team member limit until accepted.

**Q: Can removed members see historical data?**

A: No, once removed, they lose all access. Their past actions remain in audit logs for compliance purposes.

---

## Next Steps

- [Billing & Subscription](./billing-subscription.md) - Upgrade for more team members
- [Getting Started](./getting-started.md) - Onboard new team members
- [Using the Dashboards](./using-dashboards.md) - What your team can see
