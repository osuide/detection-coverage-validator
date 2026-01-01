"""
Google Workspace Setup API endpoint.

One-time setup endpoints to create and configure Workspace resources.
Requires admin authentication.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr

from app.core.security import require_role
from app.models.user import User, UserRole
from app.services.google_workspace_service import get_workspace_service

router = APIRouter()


class SetupResult(BaseModel):
    """Result of workspace setup."""

    success: bool
    message: str
    resources_created: dict


@router.post("/workspace/setup", response_model=SetupResult)
async def setup_workspace(
    current_user: User = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
) -> SetupResult:
    """
    Run one-time Google Workspace setup.

    Creates:
    - support@a13e.com collaborative inbox
    - Gmail labels for ticket management
    - Support CRM spreadsheet
    - Drive folder structure

    Requires OWNER or ADMIN role.
    """
    results = {
        "group": None,
        "labels": [],
        "folders": {},
        "spreadsheet": None,
    }
    errors = []

    try:
        ws = get_workspace_service()

        # 1. Create Support Group
        try:
            group = ws.create_google_group(
                email="support@a13e.com",
                name="A13E Support",
                description="Customer support inbox for A13E Detection Coverage Validator",
                collaborative_inbox=True,
            )
            results["group"] = group.get("email", "support@a13e.com")
        except Exception as e:
            errors.append(f"Group creation: {e}")

        # 2. Create Gmail Labels
        labels = [
            "Support/Category/Billing",
            "Support/Category/Technical",
            "Support/Category/Feature Request",
            "Support/Category/Bug Report",
            "Support/Category/Account",
            "Support/Category/Integration",
            "Support/Priority/Urgent",
            "Support/Priority/High",
            "Support/Priority/Normal",
            "Support/Priority/Low",
            "Support/Status/New",
            "Support/Status/In Progress",
            "Support/Status/Waiting on Customer",
            "Support/Status/Escalated",
            "Support/Status/Resolved",
            "Support/Status/Closed",
            "Support/Tier/Free",
            "Support/Tier/Individual",
            "Support/Tier/Pro",
            "Support/Tier/Enterprise",
            "Support/Cloud/AWS",
            "Support/Cloud/GCP",
            "Support/Cloud/Multi-Cloud",
        ]

        try:
            created_labels = ws.create_gmail_labels(labels)
            results["labels"] = [label.get("name") for label in created_labels]
        except Exception as e:
            errors.append(f"Label creation: {e}")

        # 3. Create Drive Folder Structure
        try:
            root = ws.create_drive_folder("A13E Operations")
            results["folders"]["root"] = root.get("webViewLink")

            support = ws.create_drive_folder("Support", parent_id=root["id"])
            ws.create_drive_folder("Templates", parent_id=support["id"])
            ws.create_drive_folder("Runbooks", parent_id=support["id"])
            ws.create_drive_folder("Escalations", parent_id=support["id"])

            ws.create_drive_folder("Sales", parent_id=root["id"])
            ws.create_drive_folder("Engineering", parent_id=root["id"])

            results["folders"]["support_id"] = support["id"]
        except Exception as e:
            errors.append(f"Folder creation: {e}")

        # 4. Create CRM Spreadsheet
        try:
            spreadsheet = ws.create_spreadsheet(
                title="A13E Support CRM",
                sheets=[
                    "Tickets",
                    "Customers",
                    "Metrics",
                    "Response Templates",
                    "Escalation Log",
                ],
                folder_id=results["folders"].get("support_id"),
            )
            results["spreadsheet"] = spreadsheet.get("spreadsheetUrl")

            # Add headers
            ws.sheets.spreadsheets().values().update(
                spreadsheetId=spreadsheet["spreadsheetId"],
                range="Tickets!A1:L1",
                valueInputOption="USER_ENTERED",
                body={
                    "values": [
                        [
                            "Ticket ID",
                            "Date",
                            "Customer Email",
                            "Customer Tier",
                            "Category",
                            "Priority",
                            "Status",
                            "Subject",
                            "Description",
                            "Cloud Provider",
                            "Assigned To",
                            "Resolution Notes",
                        ]
                    ]
                },
            ).execute()

            ws.sheets.spreadsheets().values().update(
                spreadsheetId=spreadsheet["spreadsheetId"],
                range="Customers!A1:H1",
                valueInputOption="USER_ENTERED",
                body={
                    "values": [
                        [
                            "Customer Email",
                            "Company",
                            "Tier",
                            "Cloud Accounts",
                            "First Contact",
                            "Last Contact",
                            "Total Tickets",
                            "Notes",
                        ]
                    ]
                },
            ).execute()

        except Exception as e:
            errors.append(f"Spreadsheet creation: {e}")

        if errors:
            return SetupResult(
                success=False,
                message=f"Partial success with errors: {'; '.join(errors)}",
                resources_created=results,
            )

        return SetupResult(
            success=True,
            message="Workspace setup completed successfully",
            resources_created=results,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Setup failed: {e}")


@router.get("/workspace/test")
async def test_workspace_connection() -> dict:
    """
    Test Google Workspace WIF connection.

    Returns connection status and basic info.
    No authentication required (for health checks).
    """
    try:
        ws = get_workspace_service()

        # Test Gmail API
        labels = ws.gmail.users().labels().list(userId="me").execute()
        label_count = len(labels.get("labels", []))

        return {
            "status": "connected",
            "wif_enabled": ws.use_wif,
            "delegated_user": ws.delegated_user,
            "gmail_labels": label_count,
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
        }


# =========================================================================
# Group Member Management
# =========================================================================


class GroupMember(BaseModel):
    """Group member details."""

    email: str
    role: str
    status: Optional[str] = None


class GroupMembersResponse(BaseModel):
    """Response for group members list."""

    group_email: str
    members: list[GroupMember]
    count: int


@router.get("/workspace/group/members", response_model=GroupMembersResponse)
async def list_support_group_members(
    group_email: str = Query(default="support@a13e.com"),
    current_user: User = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
) -> GroupMembersResponse:
    """
    List members of a Google Group.

    Requires OWNER or ADMIN role.
    """
    try:
        ws = get_workspace_service()
        members = ws.list_group_members(group_email)

        return GroupMembersResponse(
            group_email=group_email,
            members=[
                GroupMember(
                    email=m.get("email", ""),
                    role=m.get("role", "MEMBER"),
                    status=m.get("status", "ACTIVE"),
                )
                for m in members
            ],
            count=len(members),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list members: {e}")


class AddMemberRequest(BaseModel):
    """Request to add a group member."""

    member_email: EmailStr
    role: str = "MEMBER"  # MEMBER, MANAGER, or OWNER


class AddMemberResponse(BaseModel):
    """Response after adding a member."""

    success: bool
    message: str
    member: GroupMember


@router.post("/workspace/group/members", response_model=AddMemberResponse)
async def add_support_group_member(
    request: AddMemberRequest,
    group_email: str = Query(default="support@a13e.com"),
    current_user: User = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
) -> AddMemberResponse:
    """
    Add a member to a Google Group.

    Requires OWNER or ADMIN role.
    """
    try:
        ws = get_workspace_service()
        result = ws.add_group_member(
            group_email=group_email,
            member_email=request.member_email,
            role=request.role,
        )

        already_exists = result.get("status") == "exists"

        return AddMemberResponse(
            success=True,
            message=(
                f"Member {request.member_email} already exists in {group_email}"
                if already_exists
                else f"Added {request.member_email} to {group_email} as {request.role}"
            ),
            member=GroupMember(
                email=request.member_email,
                role=request.role,
                status="exists" if already_exists else "added",
            ),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add member: {e}")


@router.delete("/workspace/group/members/{member_email}")
async def remove_support_group_member(
    member_email: str,
    group_email: str = Query(default="support@a13e.com"),
    current_user: User = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
) -> dict:
    """
    Remove a member from a Google Group.

    Requires OWNER or ADMIN role.
    """
    try:
        ws = get_workspace_service()
        ws.remove_group_member(group_email, member_email)

        return {
            "success": True,
            "message": f"Removed {member_email} from {group_email}",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove member: {e}")


# =========================================================================
# Gmail Filter Setup
# =========================================================================


class FilterSetupResult(BaseModel):
    """Result of filter setup."""

    success: bool
    message: str
    filters_created: int
    details: list[dict]


@router.post("/workspace/support-filters", response_model=FilterSetupResult)
async def setup_support_filters(
    current_user: User = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
) -> FilterSetupResult:
    """
    Create Gmail filters for automatic ticket categorisation.

    Creates:
    1. Keyword-based category filters (billing, bug, feature request, etc.)
    2. Auto-apply "New" status label to incoming support emails

    Requires OWNER or ADMIN role.
    """
    ws = get_workspace_service()
    created = []
    errors = []

    # Define keyword-based filters
    keyword_filters = [
        {
            "name": "Billing",
            "keywords": "billing OR invoice OR payment OR subscription OR refund OR charge",
            "label": "Support/Category/Billing",
        },
        {
            "name": "Bug Report",
            "keywords": "bug OR error OR broken OR crash OR issue OR problem OR not working",
            "label": "Support/Category/Bug Report",
        },
        {
            "name": "Feature Request",
            "keywords": "feature OR enhancement OR request OR suggestion OR would be nice OR could you add",
            "label": "Support/Category/Feature Request",
        },
        {
            "name": "Technical",
            "keywords": "API OR integration OR scan OR detection OR coverage OR AWS OR GCP",
            "label": "Support/Category/Technical",
        },
        {
            "name": "Account",
            "keywords": "account OR password OR login OR access OR permission OR team OR invite",
            "label": "Support/Category/Account",
        },
        {
            "name": "Urgent",
            "keywords": "urgent OR emergency OR critical OR ASAP OR immediately",
            "label": "Support/Priority/Urgent",
        },
    ]

    for filter_def in keyword_filters:
        try:
            # Get label ID
            label_id = ws.get_label_id(filter_def["label"])
            if not label_id:
                errors.append(f"Label not found: {filter_def['label']}")
                continue

            # Create filter
            result = ws.create_gmail_filter(
                criteria={"subject": filter_def["keywords"]},
                action={"addLabelIds": [label_id]},
            )
            created.append(
                {
                    "name": filter_def["name"],
                    "filter_id": result.get("id"),
                    "label": filter_def["label"],
                }
            )
        except Exception as e:
            errors.append(f"Filter '{filter_def['name']}': {e}")

    # Create "New" status filter for all incoming to support@
    try:
        new_label_id = ws.get_label_id("Support/Status/New")
        if new_label_id:
            result = ws.create_gmail_filter(
                criteria={"to": "support@a13e.com"},
                action={"addLabelIds": [new_label_id]},
            )
            created.append(
                {
                    "name": "Auto-New Status",
                    "filter_id": result.get("id"),
                    "label": "Support/Status/New",
                }
            )
    except Exception as e:
        errors.append(f"New status filter: {e}")

    if errors:
        return FilterSetupResult(
            success=False,
            message=f"Created {len(created)} filters with {len(errors)} errors: {'; '.join(errors)}",
            filters_created=len(created),
            details=created,
        )

    return FilterSetupResult(
        success=True,
        message=f"Created {len(created)} Gmail filters for support categorisation",
        filters_created=len(created),
        details=created,
    )


@router.get("/workspace/filters")
async def list_gmail_filters(
    current_user: User = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
) -> dict:
    """
    List all Gmail filters.

    Requires OWNER or ADMIN role.
    """
    try:
        ws = get_workspace_service()
        filters = ws.list_gmail_filters()

        return {
            "count": len(filters),
            "filters": filters,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list filters: {e}")
