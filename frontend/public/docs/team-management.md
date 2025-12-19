# Team Management

Learn how to manage your organization's team members, roles, and permissions in A13E.

## Table of Contents

- [Overview](#overview)
- [User Roles](#user-roles)
- [Inviting Team Members](#inviting-team-members)
- [Managing Members](#managing-members)
- [Permissions Matrix](#permissions-matrix)
- [Best Practices](#best-practices)

## Overview

A13E supports team collaboration with role-based access control (RBAC). Each organization has one Owner, with optional Admins, Members, and Viewers. Each user's role determines their permissions and capabilities.

## User Roles

### Owner

Full administrative control including billing, organization deletion, and ownership transfer. Only one Owner per organization. Typical users: CISO, security team lead, organization founder.

### Admin

Manages team members and organization settings. Can invite/remove users, manage cloud accounts, run and schedule scans, and access audit logs. Cannot manage billing or delete the organization. Typical users: security engineers, team managers.

### Member

Can view and edit resources but cannot manage team or settings. Can add cloud accounts, run scans, and export reports. Cannot configure scheduled scans or access audit logs. Typical users: security analysts, DevSecOps engineers, cloud administrators.

### Viewer

Read-only access to dashboards, reports, and scan results. Cannot run scans, view credentials, or modify settings. Typical users: executives, compliance auditors, stakeholders.

## Inviting Team Members

**Who can invite**: Owner and Admin roles only. Requires available seats on your subscription plan.

**How to invite**:
1. Navigate to Settings → Team Management
2. Click **Invite Member**
3. Enter email address and select role (Viewer, Member, or Admin)
4. Add optional personal message
5. Click **Send Invite**

Invitations expire in 7 days. Invitees receive an email with an acceptance link. If they don't have an A13E account, they'll create one during acceptance. Track pending invitations in the Team Management page, where you can cancel them if needed.

## Managing Members

### Changing Member Roles

**Who can do this**: Owner and Admin (Admins cannot promote to Admin or change other Admin/Owner roles)

1. Find the member in the team list
2. Click the Actions menu (⋮)
3. Select new role: Viewer, Member, or Admin (Owner only)
4. User receives email notification of change

### Removing Team Members

**Who can do this**: Owner and Admin (Admins cannot remove other Admins or Owner)

1. Click the Actions menu (⋮) on the member's row
2. Click **Remove from team**
3. Confirm the action

Removed users lose organization access immediately but can be re-invited later. Their data is retained in audit logs.

### Transferring Ownership

**Owner only**. New owner must already be an Admin. Go to Settings → Organization → Transfer Ownership, select the new owner, and confirm with your password. This action transfers billing ownership and cannot be undone.

## Permissions Matrix

| Capability | Owner | Admin | Member | Viewer |
|------------|-------|-------|--------|--------|
| **Team Management** |
| Invite/remove members | ✓ | ✓¹ | ✗ | ✗ |
| Change roles | ✓ | ✓² | ✗ | ✗ |
| **Cloud Accounts & Scanning** |
| Add/remove accounts | ✓ | ✓ | ✓ | ✗ |
| Run scans | ✓ | ✓ | ✓ | ✗ |
| Schedule scans | ✓ | ✓ | ✗ | ✗ |
| View results/reports | ✓ | ✓ | ✓ | ✓ |
| **Organization** |
| Edit settings | ✓ | ✓ | ✗ | ✗ |
| View audit logs | ✓ | ✓ | ✗ | ✗ |
| Manage billing | ✓ | ✗ | ✗ | ✗ |
| Delete organization | ✓ | ✗ | ✗ | ✗ |

**Notes**:
1. Admins can only remove Members and Viewers
2. Admins cannot promote to Admin or change Admin/Owner roles


## Best Practices

### Role Assignment

Follow the principle of least privilege: start users with Viewer role and promote as needed. Only grant Admin to users who need team management capabilities.

**Role Selection Guide**:

| User Type | Recommended Role |
|-----------|------------------|
| Executives, compliance auditors | Viewer |
| Security analysts | Viewer or Member |
| Security engineers, cloud architects | Member or Admin |
| Team leads, CISO | Admin or Owner |

### Security Best Practices

**Access Management**:
- Review team members quarterly and remove inactive users
- Verify roles are still appropriate for each user's responsibilities
- Check audit logs regularly for anomalies

**MFA and Authentication**:
- Require MFA for Admin and Owner roles (configure in Settings → Security)
- Encourage MFA for all users
- Configure appropriate session duration based on security needs (1, 8, or 24 hours)

**Offboarding**:
When team members leave, immediately:
1. Remove user from the organization
2. Rotate shared API keys they accessed
3. Review audit logs for their recent activities
4. Reassign any scan schedules or ownership

### Subscription Management

**Plan limits**:
- **Free Scan**: 1 user only
- **Subscriber**: 5 users included, $10/month per additional user
- **Enterprise**: Unlimited users

Monitor seat usage in Settings → Billing and add seats proactively before hitting limits.

### Enterprise Features

**SSO Integration** (Enterprise plan only):
- Supported providers: Google Workspace, Okta, SAML 2.0
- Enables centralized user management and automatic provisioning
- Contact support@a13e.io for SSO setup

### Audit Logs

Owner and Admin can access audit logs in Settings → Audit Logs. Logs track user sign-ins, team changes, role updates, account additions, scan executions, and settings changes. Export logs as CSV for compliance reporting.

## Getting Help

For team management questions:
- **In-App Help**: Click the ? icon in Team Management
- **Support**: Email support@a13e.io for access issues
- **Related Docs**: See [Billing & Subscription](./billing-subscription.md) and [Getting Started](./getting-started.md)
